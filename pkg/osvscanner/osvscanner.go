package osvscanner

import (
	"bufio"
	"crypto/md5" //nolint:gosec
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/local"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/sbom"
	"github.com/google/osv-scanner/pkg/config"
	"github.com/google/osv-scanner/pkg/depsdev"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/reporter"

	depsdevpb "deps.dev/api/v3alpha"
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
	CallAnalysis          bool
	CompareLocally        bool
	CompareOffline        bool
	ShowAllPackages       bool
	ScanLicensesSummary   bool
	ScanLicensesAllowlist []string

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

//nolint:errname,stylecheck // Would require version bump to change
var LicenseViolationsErr = errors.New("license violations found")

//nolint:errname,stylecheck // Would require version bump to change
var VulnerabilitiesFoundAndLicenseViolationsErr = errors.New("vulnerabilities found and license violations found")

//nolint:errname,stylecheck // Would require version bump to change
var OnlyUncalledVulnerabilitiesFoundAndLicenseViolationsErr = errors.New("only uncalled vulnerabilities found and license violations found")

var (
	vendoredLibNames = map[string]struct{}{
		"3rdparty":    {},
		"dep":         {},
		"deps":        {},
		"thirdparty":  {},
		"third-party": {},
		"third_party": {},
		"libs":        {},
		"external":    {},
		"externals":   {},
		"vendor":      {},
		"vendored":    {},
	}
)

const (
	// This value may need to be tweaked, or be provided as a configurable flag.
	determineVersionThreshold = 0.15
	maxDetermineVersionFiles  = 10000
)

// scanDir walks through the given directory to try to find any relevant files
// These include:
//   - Any lockfiles with scanLockfile
//   - Any SBOM files with scanSBOMFile
//   - Any git repositories with scanGit
func scanDir(r reporter.Reporter, dir string, skipGit bool, recursive bool, useGitIgnore bool, compareOffline bool) ([]scannedPackage, error) {
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

	var scannedPackages []scannedPackage

	return scannedPackages, filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
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
			pkgs, err := scanGit(r, filepath.Dir(path)+"/")
			if err != nil {
				r.PrintText(fmt.Sprintf("scan failed for git repository, %s: %v\n", path, err))
				// Not fatal, so don't return and continue scanning other files
			}
			scannedPackages = append(scannedPackages, pkgs...)

			return filepath.SkipDir
		}

		if !info.IsDir() {
			if extractor, _ := lockfile.FindExtractor(path, ""); extractor != nil {
				pkgs, err := scanLockfile(r, path, "")
				if err != nil {
					r.PrintError(fmt.Sprintf("Attempted to scan lockfile but failed: %s\n", path))
				}
				scannedPackages = append(scannedPackages, pkgs...)
			}
			// No need to check for error
			// If scan fails, it means it isn't a valid SBOM file,
			// so just move onto the next file
			pkgs, _ := scanSBOMFile(r, path, true)
			scannedPackages = append(scannedPackages, pkgs...)
		}

		if info.IsDir() && !compareOffline {
			if _, ok := vendoredLibNames[strings.ToLower(filepath.Base(path))]; ok {
				pkgs, err := scanDirWithVendoredLibs(r, path)
				if err != nil {
					r.PrintText(fmt.Sprintf("scan failed for dir containing vendored libs %s: %v\n", path, err))
				}
				scannedPackages = append(scannedPackages, pkgs...)
			}
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

func queryDetermineVersions(repoDir string) (*osv.DetermineVersionResponse, error) {
	fileExts := []string{
		".hpp",
		".h",
		".hh",
		".cc",
		".c",
		".cpp",
	}

	var hashes []osv.DetermineVersionHash
	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			if _, err := os.Stat(filepath.Join(p, ".git")); err == nil {
				// Found a git repo, stop here as otherwise we may get duplicated
				// results with our regular git commit scanning.
				return filepath.SkipDir
			}
			if _, ok := vendoredLibNames[strings.ToLower(info.Name())]; ok {
				// Ignore nested vendored libraries, as they can cause bad matches.
				return filepath.SkipDir
			}

			return nil
		}
		for _, ext := range fileExts {
			if filepath.Ext(p) == ext {
				buf, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				hash := md5.Sum(buf) //nolint:gosec
				hashes = append(hashes, osv.DetermineVersionHash{
					Path: strings.ReplaceAll(p, repoDir, ""),
					Hash: hash[:],
				})
				if len(hashes) > maxDetermineVersionFiles {
					return errors.New("too many files to hash")
				}
			}
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed during hashing: %w", err)
	}

	result, err := osv.MakeDetermineVersionRequest(filepath.Base(repoDir), hashes)
	if err != nil {
		return nil, fmt.Errorf("failed to determine versions: %w", err)
	}

	return result, nil
}

func scanDirWithVendoredLibs(r reporter.Reporter, path string) ([]scannedPackage, error) {
	r.PrintText(fmt.Sprintf("Scanning directory for vendored libs: %s\n", path))
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var packages []scannedPackage
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		libPath := filepath.Join(path, entry.Name())

		r.PrintText(fmt.Sprintf("Scanning potential vendored dir: %s\n", libPath))
		// TODO: make this a goroutine to parallelise this operation
		results, err := queryDetermineVersions(libPath)
		if err != nil {
			r.PrintText(fmt.Sprintf("Error scanning sub-directory '%s' with error: %v", libPath, err))
			continue
		}

		if len(results.Matches) > 0 && results.Matches[0].Score > determineVersionThreshold {
			match := results.Matches[0]
			r.PrintText(fmt.Sprintf("Identified %s as %s at %s.\n", libPath, match.RepoInfo.Address, match.RepoInfo.Commit))
			packages = append(packages, createCommitQueryPackage(match.RepoInfo.Commit, libPath))
		}
	}

	return packages, nil
}

// gitIgnoreMatcher.match will return true if the file/directory matches a gitignore entry
// i.e. true if it should be ignored
func (m *gitIgnoreMatcher) match(absPath string, isDir bool) (bool, error) {
	pathInGit, err := filepath.Rel(m.repoPath, absPath)
	if err != nil {
		return false, err
	}
	// must prepend "." to paths because of how gitignore.ReadPatterns interprets paths
	pathInGitSep := []string{"."}
	if pathInGit != "." { // don't make the path "./."
		pathInGitSep = append(pathInGitSep, strings.Split(pathInGit, string(filepath.Separator))...)
	}

	return m.matcher.Match(pathInGitSep, isDir), nil
}

// scanLockfile will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
func scanLockfile(r reporter.Reporter, path string, parseAs string) ([]scannedPackage, error) {
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
		return nil, err
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

	packages := make([]scannedPackage, len(parsedLockfile.Packages))
	for i, pkgDetail := range parsedLockfile.Packages {
		packages[i] = scannedPackage{
			Name:      pkgDetail.Name,
			Version:   pkgDetail.Version,
			Commit:    pkgDetail.Commit,
			Ecosystem: pkgDetail.Ecosystem,
			Source: models.SourceInfo{
				Path: path,
				Type: "lockfile",
			},
		}
	}

	return packages, nil
}

// scanSBOMFile will load, identify, and parse the SBOM path passed in, and add the dependencies specified
// within to `query`
func scanSBOMFile(r reporter.Reporter, path string, fromFSScan bool) ([]scannedPackage, error) {
	var errs []error
	var packages []scannedPackage
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
			return nil, err
		}
		defer file.Close()

		ignoredCount := 0
		err = provider.GetPackages(file, func(id sbom.Identifier) error {
			_, err := models.PURLToPackage(id.PURL)
			if err != nil {
				ignoredCount++
				//nolint:nilerr
				return nil
			}
			packages = append(packages, scannedPackage{
				PURL: id.PURL,
				Source: models.SourceInfo{
					Path: path,
					Type: "sbom",
				},
			})

			return nil
		})
		if err == nil {
			// Found a parsable format.
			if len(packages) == 0 {
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
				len(packages),
				output.Form(len(packages), "package", "packages"),
			))
			if ignoredCount > 0 {
				r.PrintText(fmt.Sprintf(
					"Ignored %d %s with invalid PURLs\n",
					ignoredCount,
					output.Form(ignoredCount, "package", "packages"),
				))
			}

			return packages, nil
		}

		var formatErr sbom.InvalidFormatError
		if errors.As(err, &formatErr) {
			errs = append(errs, err)
			continue
		}

		return nil, err
	}

	// Don't log these errors if we're coming from an FS scan, since it can get very noisy.
	if !fromFSScan {
		r.PrintText("Failed to parse SBOM using all supported formats:\n")
		for _, err := range errs {
			r.PrintText(err.Error() + "\n")
		}
	}

	return packages, nil
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

func getSubmodules(repoDir string) (submodules []*git.SubmoduleStatus, err error) {
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return nil, err
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	ss, err := worktree.Submodules()
	if err != nil {
		return nil, err
	}
	for _, s := range ss {
		status, err := s.Status()
		if err != nil {
			continue
		}
		submodules = append(submodules, status)
	}

	return submodules, nil
}

// Scan git repository. Expects repoDir to end with /
func scanGit(r reporter.Reporter, repoDir string) ([]scannedPackage, error) {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return nil, err
	}
	r.PrintText(fmt.Sprintf("Scanning %s at commit %s\n", repoDir, commit))

	//nolint:prealloc // Not sure how many there will be in advance.
	var packages []scannedPackage
	packages = append(packages, createCommitQueryPackage(commit, repoDir))

	submodules, err := getSubmodules(repoDir)
	if err != nil {
		return nil, err
	}

	for _, s := range submodules {
		r.PrintText(fmt.Sprintf("Scanning submodule %s at commit %s\n", s.Path, s.Expected.String()))
		packages = append(packages, createCommitQueryPackage(s.Expected.String(), path.Join(repoDir, s.Path)))
	}

	return packages, nil
}

func createCommitQueryPackage(commit string, source string) scannedPackage {
	return scannedPackage{
		Commit: commit,
		Source: models.SourceInfo{
			Path: source,
			Type: "git",
		},
	}
}

func scanDebianDocker(r reporter.Reporter, dockerImageName string) ([]scannedPackage, error) {
	cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "/usr/bin/dpkg-query", dockerImageName, "-f", "${Package}###${Version}\\n", "-W")
	stdout, err := cmd.StdoutPipe()

	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to get stdout: %s\n", err))
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to start docker image: %s\n", err))
		return nil, err
	}
	// TODO: Do error checking here
	//nolint:errcheck
	defer cmd.Wait()
	scanner := bufio.NewScanner(stdout)
	var packages []scannedPackage
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		if len(text) == 0 {
			continue
		}
		splitText := strings.Split(text, "###")
		if len(splitText) != 2 {
			r.PrintError(fmt.Sprintf("Unexpected output from Debian container: \n\n%s\n", text))
			return nil, fmt.Errorf("unexpected output from Debian container: \n\n%s", text)
		}
		// TODO(rexpan): Get and specify exact debian release version
		packages = append(packages, scannedPackage{
			Name:      splitText[0],
			Version:   splitText[1],
			Ecosystem: "Debian",
			Source: models.SourceInfo{
				Path: dockerImageName,
				Type: "docker",
			},
		})
	}
	r.PrintText(fmt.Sprintf(
		"Scanned docker image with %d %s\n",
		len(packages),
		output.Form(len(packages), "package", "packages"),
	))

	return packages, nil
}

// Filters results according to config, preserving order. Returns total number of vulnerabilities removed.
func filterResults(r reporter.Reporter, results *models.VulnerabilityResults, configManager *config.ConfigManager, allPackages bool) int {
	removedCount := 0
	newResults := []models.PackageSource{} // Want 0 vulnerabilities to show in JSON as an empty list, not null.
	for _, pkgSrc := range results.Results {
		configToUse := configManager.Get(r, pkgSrc.Source.Path)
		var newPackages []models.PackageVulns
		for _, pkgVulns := range pkgSrc.Packages {
			newVulns := filterPackageVulns(r, pkgVulns, configToUse)
			removedCount += len(pkgVulns.Vulnerabilities) - len(newVulns.Vulnerabilities)
			if allPackages || len(newVulns.Vulnerabilities) > 0 || len(pkgVulns.LicenseViolations) > 0 {
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

type scannedPackage struct {
	PURL      string
	Name      string
	Ecosystem lockfile.Ecosystem
	Commit    string
	Version   string
	Source    models.SourceInfo
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

	//nolint:prealloc // Not sure how many there will be in advance.
	var scannedPackages []scannedPackage

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
		pkgs, _ := scanDebianDocker(r, container)
		scannedPackages = append(scannedPackages, pkgs...)
	}

	for _, lockfileElem := range actions.LockfilePaths {
		parseAs, lockfilePath := parseLockfilePath(lockfileElem)
		lockfilePath, err := filepath.Abs(lockfilePath)
		if err != nil {
			r.PrintError(fmt.Sprintf("Failed to resolved path with error %s\n", err))
			return models.VulnerabilityResults{}, err
		}
		pkgs, err := scanLockfile(r, lockfilePath, parseAs)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	for _, sbomElem := range actions.SBOMPaths {
		sbomElem, err := filepath.Abs(sbomElem)
		if err != nil {
			return models.VulnerabilityResults{}, fmt.Errorf("failed to resolved path with error %w", err)
		}
		pkgs, err := scanSBOMFile(r, sbomElem, false)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	for _, commit := range actions.GitCommits {
		scannedPackages = append(scannedPackages, createCommitQueryPackage(commit, "HASH"))
	}

	for _, dir := range actions.DirectoryPaths {
		r.PrintText(fmt.Sprintf("Scanning dir %s\n", dir))
		pkgs, err := scanDir(r, dir, actions.SkipGit, actions.Recursive, !actions.NoIgnore, actions.CompareOffline)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	if len(scannedPackages) == 0 {
		return models.VulnerabilityResults{}, NoPackagesFoundErr
	}

	filteredScannedPackages := filterUnscannablePackages(scannedPackages)

	if len(filteredScannedPackages) != len(scannedPackages) {
		r.PrintText(fmt.Sprintf("Filtered %d local package/s from the scan.\n", len(scannedPackages)-len(filteredScannedPackages)))
	}

	vulnsResp, err := makeRequest(r, filteredScannedPackages, actions.CompareLocally, actions.CompareOffline, actions.LocalDBPath)
	if err != nil {
		return models.VulnerabilityResults{}, err
	}

	var licensesResp [][]models.License
	if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
		licensesResp, err = makeLicensesRequests(filteredScannedPackages)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}
	results := buildVulnerabilityResults(r, filteredScannedPackages, vulnsResp, licensesResp, actions)

	filtered := filterResults(r, &results, &configManager, actions.ShowAllPackages)
	if filtered > 0 {
		r.PrintText(fmt.Sprintf(
			"Filtered %d %s from output\n",
			filtered,
			output.Form(filtered, "vulnerability", "vulnerabilities"),
		))
	}

	if len(results.Results) > 0 {
		// Determine the correct error to return.
		// TODO: in the next breaking release of osv-scanner, consider
		// returning a ScanError instead of an error.
		var vuln bool
		onlyUncalledVuln := true
		var licenseViolation bool
		for _, vf := range results.Flatten() {
			if vf.Vulnerability.ID != "" {
				vuln = true
				if vf.GroupInfo.IsCalled() {
					onlyUncalledVuln = false
				}
			}
			if len(vf.LicenseViolations) > 0 {
				licenseViolation = true
			}
		}
		onlyUncalledVuln = onlyUncalledVuln && vuln
		licenseViolation = licenseViolation && len(actions.ScanLicensesAllowlist) > 0

		switch {
		case !vuln && !onlyUncalledVuln && !licenseViolation:
			// There is no error.
			return results, nil
		case vuln && !onlyUncalledVuln && !licenseViolation:
			return results, VulnerabilitiesFoundErr
		case !vuln && onlyUncalledVuln && !licenseViolation:
			// Impossible state.
			panic("internal error: uncalled vulnerabilities exist but no vulnerabilities exist")
		case vuln && onlyUncalledVuln && !licenseViolation:
			return results, OnlyUncalledVulnerabilitiesFoundErr
		case !vuln && !onlyUncalledVuln && licenseViolation:
			return results, LicenseViolationsErr
		case vuln && !onlyUncalledVuln && licenseViolation:
			return results, VulnerabilitiesFoundAndLicenseViolationsErr
		case !vuln && onlyUncalledVuln && licenseViolation:
			panic("internal error: uncalled vulnerabilities exist but no vulnerabilities exist")
		case vuln && onlyUncalledVuln && licenseViolation:
			return results, OnlyUncalledVulnerabilitiesFoundAndLicenseViolationsErr
		}
	}

	return results, nil
}

// filterUnscannablePackages removes packages that don't have enough information to be scanned
// e,g, local packages that specified by path
func filterUnscannablePackages(packages []scannedPackage) []scannedPackage {
	out := make([]scannedPackage, 0, len(packages))
	for _, p := range packages {
		switch {
		// If none of the cases match, skip this package since it's not scannable
		case p.Ecosystem != "" && p.Name != "" && p.Version != "":
		case p.Commit != "":
		case p.PURL != "":
		default:
			continue
		}
		out = append(out, p)
	}

	return out
}

func makeRequest(
	r reporter.Reporter,
	packages []scannedPackage,
	compareLocally bool,
	compareOffline bool,
	localDBPath string) (*osv.HydratedBatchedResponse, error) {
	// Make OSV queries from the packages.
	var query osv.BatchedQuery
	for _, p := range packages {
		switch {
		// Prefer making package requests where possible.
		case p.Ecosystem != "" && p.Name != "" && p.Version != "":
			query.Queries = append(query.Queries, osv.MakePkgRequest(lockfile.PackageDetails{
				Name:      p.Name,
				Version:   p.Version,
				Ecosystem: p.Ecosystem,
			}))
		case p.Commit != "":
			query.Queries = append(query.Queries, osv.MakeCommitRequest(p.Commit))
		case p.PURL != "":
			query.Queries = append(query.Queries, osv.MakePURLRequest(p.PURL))
		default:
			return nil, fmt.Errorf("package %v does not have a commit, PURL or ecosystem/name/version identifier", p)
		}
	}

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

func makeLicensesRequests(packages []scannedPackage) ([][]models.License, error) {
	queries := make([]*depsdevpb.GetVersionRequest, len(packages))
	for i, pkg := range packages {
		system, ok := depsdev.System[pkg.Ecosystem]
		if !ok || pkg.Name == "" || pkg.Version == "" {
			continue
		}
		queries[i] = depsdev.VersionQuery(system, pkg.Name, pkg.Version)
	}
	licenses, err := depsdev.MakeVersionRequests(queries)
	if err != nil {
		return nil, err
	}

	return licenses, nil
}
