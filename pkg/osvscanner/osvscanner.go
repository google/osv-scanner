package osvscanner

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/osv"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/sbom"
	"github.com/google/osv-scanner/pkg/config"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
)

type ScannerActions struct {
	LockfilePaths        []string
	SBOMPaths            []string
	DirectoryPaths       []string
	GitCommits           []string
	Recursive            bool
	SkipGit              bool
	DockerContainerNames []string
	ConfigOverridePath   string
}

// Error for when no packages is found during a scan.
var NoPackagesFoundErr = errors.New("no packages found in scan")
var VulnerabilitiesFoundErr = errors.New("vulnerabilities found")

// scanDir walks through the given directory to try to find any relevant files
// These include:
//   - Any lockfiles with scanLockfile
//   - Any SBOM files with scanSBOMFile
//   - Any git repositories with scanGit
func scanDir(r *output.Reporter, query *osv.BatchedQuery, dir string, skipGit bool, recursive bool) error {
	root := true
	return filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			r.PrintText(fmt.Sprintf("Failed to walk %s: %v\n", path, err))
			return err
		}
		path, err = filepath.Abs(path)
		if err != nil {
			r.PrintError(fmt.Sprintf("Failed to walk path %s\n", err))
			return err
		}

		if !skipGit && info.IsDir() && info.Name() == ".git" {
			err := scanGit(r, query, filepath.Dir(path)+"/")
			if err != nil {
				r.PrintText(fmt.Sprintf("scan failed for git repository, %s: %v\n", path, err))
				// Not fatal, so don't return and continue scanning other files
			}
			return filepath.SkipDir
		}

		if !info.IsDir() {
			if parser, _ := lockfile.FindParser(path, ""); parser != nil {
				err := scanLockfile(r, query, path)
				if err != nil {
					r.PrintError(fmt.Sprintf("Attempted to scan lockfile but failed: %s\n", path))
				}
			}
			// No need to check for error
			// If scan fails, it means it isn't a valid SBOM file,
			// so just move onto the next file
			_ = scanSBOMFile(r, query, path)
		}

		if !root && !recursive && info.IsDir() {
			return filepath.SkipDir
		}
		root = false

		return nil
	})
}

// scanLockfile will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
func scanLockfile(r *output.Reporter, query *osv.BatchedQuery, path string) error {
	parsedLockfile, err := lockfile.Parse(path, "")
	if err != nil {
		return err
	}
	r.PrintText(fmt.Sprintf("Scanned %s file and found %d packages\n", path, len(parsedLockfile.Packages)))

	for _, pkgDetail := range parsedLockfile.Packages {
		pkgDetailQuery := osv.MakePkgRequest(pkgDetail)
		pkgDetailQuery.Source = models.SourceInfo{
			Path: path,
			Type: "lockfile",
		}
		query.Queries = append(query.Queries, pkgDetailQuery)
	}
	return nil
}

// scanSBOMFile will load, identify, and parse the SBOM path passed in, and add the dependencies specified
// within to `query`
func scanSBOMFile(r *output.Reporter, query *osv.BatchedQuery, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	for _, provider := range sbom.Providers {
		if provider.Name() == "SPDX" &&
			!strings.Contains(strings.ToLower(filepath.Base(path)), ".spdx") {
			// All spdx files should have the .spdx in the filename, even if
			// it's not the extension:  https://spdx.github.io/spdx-spec/v2.3/conformance/
			// Skip if this isn't the case to avoid panics
			continue
		}
		err := provider.GetPackages(file, func(id sbom.Identifier) error {
			purlQuery := osv.MakePURLRequest(id.PURL)
			purlQuery.Source = models.SourceInfo{
				Path: path,
				Type: "sbom",
			}
			query.Queries = append(query.Queries, purlQuery)
			return nil
		})
		if err == nil {
			// Found the right format.
			r.PrintText(fmt.Sprintf("Scanned %s SBOM\n", provider.Name()))
			return nil
		}

		if errors.Is(err, sbom.InvalidFormat) {
			continue
		}

		return err
	}

	return nil
}

func getCommitSHA(repoDir string) (string, error) {
	cmd := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD")
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()

	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok && exiterr.ExitCode() == 128 {
			return "", fmt.Errorf("Failed to get commit hash, no commits exist? %w", exiterr)
		} else {
			return "", fmt.Errorf("failed to get commit hash: %w", err)
		}
	}

	return strings.TrimSpace(out.String()), nil
}

// Scan git repository. Expects repoDir to end with /
func scanGit(r *output.Reporter, query *osv.BatchedQuery, repoDir string) error {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return err
	}
	r.PrintText(fmt.Sprintf("Scanning %s at commit %s\n", repoDir, commit))

	return scanGitCommit(r, query, commit, repoDir)
}

func scanGitCommit(r *output.Reporter, query *osv.BatchedQuery, commit string, source string) error {
	gitQuery := osv.MakeCommitRequest(commit)
	gitQuery.Source = models.SourceInfo{
		Path: source,
		Type: "git",
	}
	query.Queries = append(query.Queries, gitQuery)
	return nil
}

func scanDebianDocker(r *output.Reporter, query *osv.BatchedQuery, dockerImageName string) error {
	cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "/usr/bin/dpkg-query", dockerImageName, "-f", "${Package}###${Version}\\n", "-W")
	stdout, err := cmd.StdoutPipe()

	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to get stdout: %s\n", err))
		return err
	}
	err = cmd.Start()
	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to start docker image: %s\n", err))
		return err
	}
	defer cmd.Wait()
	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to run docker: %s\n", err))
		return err
	}
	scanner := bufio.NewScanner(stdout)
	packages := 0
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		if len(text) == 0 {
			continue
		}
		splitText := strings.Split(text, "###")
		if len(splitText) != 2 {
			r.PrintError(fmt.Sprintf("Unexpected output from Debian container: \n\n%s\n", text))
			return fmt.Errorf("unexpected output from Debian container: \n\n%s", text)
		}
		pkgDetailsQuery := osv.MakePkgRequest(lockfile.PackageDetails{
			Name:    splitText[0],
			Version: splitText[1],
			// TODO(rexpan): Get and specify exact debian release version
			Ecosystem: "Debian",
		})
		pkgDetailsQuery.Source = models.SourceInfo{
			Path: dockerImageName,
			Type: "docker",
		}
		query.Queries = append(query.Queries, pkgDetailsQuery)
		packages += 1
	}
	r.PrintText(fmt.Sprintf("Scanned docker image with %d packages\n", packages))

	return nil
}

// Filters response according to config, returns number of responses removed
func filterResponse(r *output.Reporter, query osv.BatchedQuery, resp *osv.BatchedResponse, configManager *config.ConfigManager) int {
	hiddenVulns := map[string]config.IgnoreEntry{}

	for i, result := range resp.Results {
		var filteredVulns []osv.MinimalVulnerability
		configToUse := configManager.Get(r, query.Queries[i].Source.Path)
		for _, vuln := range result.Vulns {
			ignore, ignoreLine := configToUse.ShouldIgnore(vuln.ID)
			if ignore {
				hiddenVulns[vuln.ID] = ignoreLine
			} else {
				filteredVulns = append(filteredVulns, vuln)
			}
		}
		resp.Results[i].Vulns = filteredVulns
	}

	for id, ignoreLine := range hiddenVulns {
		r.PrintText(fmt.Sprintf("%s has been filtered out because: %s\n", id, ignoreLine.Reason))
	}

	return len(hiddenVulns)
}

// Perform osv scanner action, with optional reporter to output information
func DoScan(actions ScannerActions, r *output.Reporter) (models.VulnerabilityResults, error) {
	if r == nil {
		r = output.NewVoidReporter()
	}

	configManager := config.ConfigManager{
		DefaultConfig: config.Config{},
		ConfigMap:     make(map[string]config.Config),
	}

	var query osv.BatchedQuery

	if actions.ConfigOverridePath != "" {
		err := configManager.UseOverride(actions.ConfigOverridePath)
		if err != nil {
			r.PrintError(fmt.Sprintf("Failed to read config file: %s\n", err))
			return models.VulnerabilityResults{}, err
		}
	}

	for _, container := range actions.DockerContainerNames {
		// TODO: Automatically figure out what docker base image
		// and scan appropriately.
		scanDebianDocker(r, &query, container)
	}

	for _, lockfileElem := range actions.LockfilePaths {
		lockfileElem, err := filepath.Abs(lockfileElem)
		if err != nil {
			r.PrintError(fmt.Sprintf("Failed to resolved path with error %s\n", err))
			return models.VulnerabilityResults{}, err
		}
		err = scanLockfile(r, &query, lockfileElem)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	for _, sbomElem := range actions.SBOMPaths {
		sbomElem, err := filepath.Abs(sbomElem)
		if err != nil {
			return models.VulnerabilityResults{}, fmt.Errorf("failed to resolved path with error %s\n", err)
		}
		err = scanSBOMFile(r, &query, sbomElem)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	for _, commit := range actions.GitCommits {
		err := scanGitCommit(r, &query, commit, "HASH")
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	for _, dir := range actions.DirectoryPaths {
		r.PrintText(fmt.Sprintf("Scanning dir %s\n", dir))
		err := scanDir(r, &query, dir, actions.SkipGit, actions.Recursive)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	if len(query.Queries) == 0 {
		return models.VulnerabilityResults{}, NoPackagesFoundErr
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("scan failed %v", err)
	}

	filtered := filterResponse(r, query, resp, &configManager)
	if filtered > 0 {
		r.PrintText(fmt.Sprintf("Filtered %d vulnerabilities from output\n", filtered))
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("failed to hydrate OSV response: %v", err)
	}

	vulnerabilityResults := groupResponseBySource(r, query, hydratedResp)
	// if vulnerability exists it should return error
	if len(vulnerabilityResults.Results) > 0 {
		return vulnerabilityResults, VulnerabilitiesFoundErr
	}

	return vulnerabilityResults, nil
}
