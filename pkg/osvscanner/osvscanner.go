package osvscanner

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/local"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/sbom"
	"github.com/google/osv-scanner/pkg/config"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/reporter"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

type ScannerActions struct {
	LockfilePaths        []string
	SBOMPaths            []string
	DirectoryPaths       []string
	GitCommits           []string
	Recursive            bool
	SkipGit              bool
	NoIgnore             bool
	DockerContainerNames []string
	ConfigOverridePath   string

	ExperimentalScannerActions
}

type ExperimentalScannerActions struct {
	CallAnalysis   bool
	CompareLocally bool
	CompareOffline bool

	LocalDBPath string
}

// NoPackagesFoundErr for when no packages are found during a scan.
//
//nolint:errname,stylecheck // Would require version major bump to change
var NoPackagesFoundErr = errors.New("no packages found in scan")

//nolint:errname,stylecheck // Would require version major bump to change
var VulnerabilitiesFoundErr = errors.New("vulnerabilities found")

//nolint:errname,stylecheck // Would require version bump to change
var OnlyUncalledVulnerabilitiesFoundErr = errors.New("only uncalled vulnerabilities found")

// scanDir walks through the given directory to try to find any relevant files
// These include:
//   - Any lockfiles with scanLockfile
//   - Any SBOM files with scanSBOMFile
//   - Any git repositories with scanGit
func scanDir(r reporter.Reporter, query *osv.BatchedQuery, dir string, skipGit bool, recursive bool, useGitIgnore bool) error {
	var ignoreMatcher *gitIgnoreMatcher
	if useGitIgnore {
		var err error
		ignoreMatcher, err = parseGitIgnores(dir)
		if err != nil {
			r.PrintError(fmt.Sprintf("Unable to parse git ignores: %v\n", err))
			useGitIgnore = false
		}
	}

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

		if useGitIgnore {
			match, err := ignoreMatcher.match(path, info.IsDir())
			if err != nil {
				r.PrintText(fmt.Sprintf("Failed to resolve gitignore for %s: %v\n", path, err))
				// Don't skip if we can't parse now - potentially noisy for directories with lots of items
			} else if match {
				if root { // Don't silently skip if the argument file was ignored.
					r.PrintError(fmt.Sprintf("%s was not scanned because it is excluded by a .gitignore file. Use --no-ignore to scan it.\n", path))
				}
				if info.IsDir() {
					return filepath.SkipDir
				}

				return nil
			}
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
			if extractor, _ := lockfile.FindExtractor(path, ""); extractor != nil {
				err := scanLockfile(r, query, path, "")
				if err != nil {
					r.PrintError(fmt.Sprintf("Attempted to scan lockfile but failed: %s\n", path))
				}
			}
			// No need to check for error
			// If scan fails, it means it isn't a valid SBOM file,
			// so just move onto the next file
			_ = scanSBOMFile(r, query, path, true)
		}

		if !root && !recursive && info.IsDir() {
			return filepath.SkipDir
		}
		root = false

		return nil
	})
}

type gitIgnoreMatcher struct {
	matcher  gitignore.Matcher
	repoPath string
}

func parseGitIgnores(path string) (*gitIgnoreMatcher, error) {
	// We need to parse .gitignore files from the root of the git repo to correctly identify ignored files
	var fs billy.Filesystem

	// Default to path (or directory containing path if it's a file) is not in a repo or some other error
	finfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if finfo.IsDir() {
		fs = osfs.New(path)
	} else {
		fs = osfs.New(filepath.Dir(path))
	}

	if repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true}); err == nil {
		if tree, err := repo.Worktree(); err == nil {
			fs = tree.Filesystem
		}
	}

	patterns, err := gitignore.ReadPatterns(fs, []string{"."})
	if err != nil {
		return nil, err
	}
	matcher := gitignore.NewMatcher(patterns)
	repopath, err := filepath.Abs(fs.Root())
	if err != nil {
		return nil, err
	}

	return &gitIgnoreMatcher{matcher: matcher, repoPath: repopath}, nil
}

// gitIgnoreMatcher.match will return true if the file/directory matches a gitignore entry
// i.e. true if it should be ignored
func (m *gitIgnoreMatcher) match(absPath string, isDir bool) (bool, error) {
	pathInGit, err := filepath.Rel(m.repoPath, absPath)
	if err != nil {
		return false, err
	}
	// must prepend "." to paths because of how gitignore.ReadPatterns interprets paths
	pathInGitSep := append([]string{"."}, strings.Split(pathInGit, string(filepath.Separator))...)

	return m.matcher.Match(pathInGitSep, isDir), nil
}

// scanLockfile will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
func scanLockfile(r reporter.Reporter, query *osv.BatchedQuery, path string, parseAs string) error {
	var err error
	var parsedLockfile lockfile.Lockfile

	f, err := lockfile.OpenLocalDepFile(path)

	if err == nil {
		// special case for the APK and DPKG parsers because they have a very generic name while
		// living at a specific location, so they are not included in the map of parsers
		// used by lockfile.Parse to avoid false-positives when scanning projects
		switch parseAs {
		case "apk-installed":
			parsedLockfile, err = lockfile.FromApkInstalled(path)
		case "dpkg-status":
			parsedLockfile, err = lockfile.FromDpkgStatus(path)
		case "osv-scanner":
			parsedLockfile, err = lockfile.FromOSVScannerResults(path)
		default:
			parsedLockfile, err = lockfile.ExtractDeps(f, parseAs)
		}
	}

	if err != nil {
		return err
	}

	addCompilerVersion(r, &parsedLockfile)

	parsedAsComment := ""

	if parseAs != "" {
		parsedAsComment = fmt.Sprintf("as a %s ", parseAs)
	}

	r.PrintText(fmt.Sprintf(
		"Scanned %s file %sand found %d %s\n",
		path,
		parsedAsComment,
		len(parsedLockfile.Packages),
		output.Form(len(parsedLockfile.Packages), "package", "packages"),
	))

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
func scanSBOMFile(r reporter.Reporter, query *osv.BatchedQuery, path string, fromFSScan bool) error {
	var errs []error
	for _, provider := range sbom.Providers {
		if fromFSScan && !provider.MatchesRecognizedFileNames(path) {
			// Skip if filename is not usually a sbom file of this format.
			// Only do this if this is being done in a filesystem scanning context, where we need to be
			// careful about spending too much time attempting to parse unrelated files.
			// If this is coming from an explicit scan argument, be more relaxed here since it's common for
			// filenames to not conform to expected filename standards.
			continue
		}

		// Opening file inside loop is OK, since providers is not very long,
		// and it is unlikely that multiple providers accept the same file name
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		count := 0
		ignoredCount := 0
		err = provider.GetPackages(file, func(id sbom.Identifier) error {
			_, err := models.PURLToPackage(id.PURL)
			if err != nil {
				ignoredCount++
				//nolint:nilerr
				return nil
			}
			purlQuery := osv.MakePURLRequest(id.PURL)
			purlQuery.Source = models.SourceInfo{
				Path: path,
				Type: "sbom",
			}
			query.Queries = append(query.Queries, purlQuery)
			count++

			return nil
		})
		if err == nil {
			// Found a parsable format.
			if count == 0 {
				// But no entries found, so maybe not the correct format
				errs = append(errs, sbom.InvalidFormatError{
					Msg: "no Package URLs found",
					Errs: []error{
						fmt.Errorf("scanned %s as %s SBOM, but failed to find any package URLs, this is required to scan SBOMs", path, provider.Name()),
					},
				})

				continue
			}
			r.PrintText(fmt.Sprintf(
				"Scanned %s as %s SBOM and found %d %s\n",
				path,
				provider.Name(),
				count,
				output.Form(count, "package", "packages"),
			))
			if ignoredCount > 0 {
				r.PrintText(fmt.Sprintf(
					"Ignored %d %s with invalid PURLs\n",
					ignoredCount,
					output.Form(ignoredCount, "package", "packages"),
				))
			}

			return nil
		}

		var formatErr sbom.InvalidFormatError
		if errors.As(err, &formatErr) {
			errs = append(errs, err)
			continue
		}

		return err
	}

	// Don't log these errors if we're coming from an FS scan, since it can get very noisy.
	if !fromFSScan {
		r.PrintText("Failed to parse SBOM using all supported formats:\n")
		for _, err := range errs {
			r.PrintText(err.Error() + "\n")
		}
	}

	return nil
}

func getCommitSHA(repoDir string) (string, error) {
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return "", err
	}
	head, err := repo.Head()
	if err != nil {
		return "", err
	}

	return head.Hash().String(), nil
}

// Scan git repository. Expects repoDir to end with /
func scanGit(r reporter.Reporter, query *osv.BatchedQuery, repoDir string) error {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return err
	}
	r.PrintText(fmt.Sprintf("Scanning %s at commit %s\n", repoDir, commit))

	return scanGitCommit(query, commit, repoDir)
}

func scanGitCommit(query *osv.BatchedQuery, commit string, source string) error {
	gitQuery := osv.MakeCommitRequest(commit)
	gitQuery.Source = models.SourceInfo{
		Path: source,
		Type: "git",
	}
	query.Queries = append(query.Queries, gitQuery)

	return nil
}

func scanDebianDocker(r reporter.Reporter, query *osv.BatchedQuery, dockerImageName string) error {
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
	// TODO: Do error checking here
	//nolint:errcheck
	defer cmd.Wait()
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
	r.PrintText(fmt.Sprintf(
		"Scanned docker image with %d %s\n",
		packages,
		output.Form(packages, "package", "packages"),
	))

	return nil
}

// Filters results according to config, preserving order. Returns total number of vulnerabilities removed.
func filterResults(r reporter.Reporter, results *models.VulnerabilityResults, configManager *config.ConfigManager) int {
	removedCount := 0
	newResults := []models.PackageSource{} // Want 0 vulnerabilities to show in JSON as an empty list, not null.
	for _, pkgSrc := range results.Results {
		configToUse := configManager.Get(r, pkgSrc.Source.Path)
		var newPackages []models.PackageVulns
		for _, pkgVulns := range pkgSrc.Packages {
			newVulns := filterPackageVulns(r, pkgVulns, configToUse)
			removedCount += len(pkgVulns.Vulnerabilities) - len(newVulns.Vulnerabilities)
			// Don't want to include the package at all if there are no vulns.
			if len(newVulns.Vulnerabilities) > 0 {
				newPackages = append(newPackages, newVulns)
			}
		}
		// Don't want to include the package source at all if there are no vulns.
		if len(newPackages) > 0 {
			pkgSrc.Packages = newPackages
			newResults = append(newResults, pkgSrc)
		}
	}
	results.Results = newResults

	return removedCount
}

// Filters package-grouped vulnerabilities according to config, preserving ordering. Returns filtered package vulnerabilities.
func filterPackageVulns(r reporter.Reporter, pkgVulns models.PackageVulns, configToUse config.Config) models.PackageVulns {
	ignoredVulns := map[string]struct{}{}
	// Iterate over groups first to remove all aliases of ignored vulnerabilities.
	var newGroups []models.GroupInfo
	for _, group := range pkgVulns.Groups {
		ignore := false
		for _, id := range group.IDs {
			var ignoreLine config.IgnoreEntry
			if ignore, ignoreLine = configToUse.ShouldIgnore(id); ignore {
				for _, id := range group.IDs {
					ignoredVulns[id] = struct{}{}
				}
				// NB: This only prints the first reason encountered in all the aliases.
				switch len(group.IDs) {
				case 1:
					r.PrintText(fmt.Sprintf("%s has been filtered out because: %s\n", ignoreLine.ID, ignoreLine.Reason))
				case 2:
					r.PrintText(fmt.Sprintf("%s and 1 alias have been filtered out because: %s\n", ignoreLine.ID, ignoreLine.Reason))
				default:
					r.PrintText(fmt.Sprintf("%s and %d aliases have been filtered out because: %s\n", ignoreLine.ID, len(group.IDs)-1, ignoreLine.Reason))
				}

				break
			}
		}
		if !ignore {
			newGroups = append(newGroups, group)
		}
	}

	var newVulns []models.Vulnerability
	if len(newGroups) > 0 { // If there are no groups left then there would be no vulnerabilities.
		for _, vuln := range pkgVulns.Vulnerabilities {
			if _, filtered := ignoredVulns[vuln.ID]; !filtered {
				newVulns = append(newVulns, vuln)
			}
		}
	}

	// Passed by value. We don't want to alter the original PackageVulns.
	pkgVulns.Groups = newGroups
	pkgVulns.Vulnerabilities = newVulns

	return pkgVulns
}

func parseLockfilePath(lockfileElem string) (string, string) {
	if !strings.Contains(lockfileElem, ":") {
		lockfileElem = ":" + lockfileElem
	}

	splits := strings.SplitN(lockfileElem, ":", 2)

	return splits[0], splits[1]
}

// Perform osv scanner action, with optional reporter to output information
func DoScan(actions ScannerActions, r reporter.Reporter) (models.VulnerabilityResults, error) {
	if r == nil {
		r = &reporter.VoidReporter{}
	}

	if actions.CompareOffline {
		actions.CompareLocally = true
	}

	if actions.CompareLocally {
		actions.SkipGit = true
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
		_ = scanDebianDocker(r, &query, container)
	}

	for _, lockfileElem := range actions.LockfilePaths {
		parseAs, lockfilePath := parseLockfilePath(lockfileElem)
		lockfilePath, err := filepath.Abs(lockfilePath)
		if err != nil {
			r.PrintError(fmt.Sprintf("Failed to resolved path with error %s\n", err))
			return models.VulnerabilityResults{}, err
		}
		err = scanLockfile(r, &query, lockfilePath, parseAs)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	for _, sbomElem := range actions.SBOMPaths {
		sbomElem, err := filepath.Abs(sbomElem)
		if err != nil {
			return models.VulnerabilityResults{}, fmt.Errorf("failed to resolved path with error %w", err)
		}
		err = scanSBOMFile(r, &query, sbomElem, false)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	for _, commit := range actions.GitCommits {
		err := scanGitCommit(&query, commit, "HASH")
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	for _, dir := range actions.DirectoryPaths {
		r.PrintText(fmt.Sprintf("Scanning dir %s\n", dir))
		err := scanDir(r, &query, dir, actions.SkipGit, actions.Recursive, !actions.NoIgnore)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	if len(query.Queries) == 0 {
		return models.VulnerabilityResults{}, NoPackagesFoundErr
	}

	hydratedResp, err := makeRequest(r, actions.CompareLocally, actions.CompareOffline, query, actions.LocalDBPath)

	if err != nil {
		return models.VulnerabilityResults{}, err
	}

	vulnerabilityResults := buildVulnerabilityResults(r, query, hydratedResp, actions.CallAnalysis)

	filtered := filterResults(r, &vulnerabilityResults, &configManager)
	if filtered > 0 {
		r.PrintText(fmt.Sprintf(
			"Filtered %d %s from output\n",
			filtered,
			output.Form(filtered, "vulnerability", "vulnerabilities"),
		))
	}

	// if vulnerability exists it should return error
	if len(vulnerabilityResults.Results) > 0 {
		// If any vulnerabilities are called, then we return VulnerabilitiesFoundErr
		for _, vf := range vulnerabilityResults.Flatten() {
			if vf.GroupInfo.IsCalled() {
				return vulnerabilityResults, VulnerabilitiesFoundErr
			}
		}
		// Otherwise return OnlyUncalledVulnerabilitiesFoundErr
		return vulnerabilityResults, OnlyUncalledVulnerabilitiesFoundErr
	}

	return vulnerabilityResults, nil
}

func makeRequest(
	r reporter.Reporter,
	compareLocally bool,
	compareOffline bool,
	query osv.BatchedQuery,
	localDBPath string,
) (*osv.HydratedBatchedResponse, error) {
	if compareLocally {
		hydratedResp, err := local.MakeRequest(r, query, compareOffline, localDBPath)
		if err != nil {
			return &osv.HydratedBatchedResponse{}, fmt.Errorf("scan failed %w", err)
		}

		return hydratedResp, nil
	}

	if osv.RequestUserAgent == "" {
		osv.RequestUserAgent = "osv-scanner-api"
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("scan failed %w", err)
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("failed to hydrate OSV response: %w", err)
	}

	return hydratedResp, nil
}
