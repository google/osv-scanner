package osvscanner

import (
	"bufio"
	"cmp"
	"context"
	"crypto/md5" //nolint:gosec
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	scalibrosv "github.com/google/osv-scalibr/extractor/filesystem/osv"

	"github.com/google/osv-scanner/internal/config"
	"github.com/google/osv-scanner/internal/customgitignore"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/image"
	"github.com/google/osv-scanner/internal/local"
	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/pomxmlnet"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/sbom"
	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/reporter"

	depsdevpb "deps.dev/api/v3"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

type ScannerActions struct {
	LockfilePaths      []string
	SBOMPaths          []string
	DirectoryPaths     []string
	GitCommits         []string
	Recursive          bool
	SkipGit            bool
	NoIgnore           bool
	DockerImageName    string
	ConfigOverridePath string
	CallAnalysisStates map[string]bool

	ExperimentalScannerActions
}

type ExperimentalScannerActions struct {
	CompareOffline        bool
	DownloadDatabases     bool
	ShowAllPackages       bool
	ScanLicensesSummary   bool
	ScanLicensesAllowlist []string
	ScanOCIImage          string

	LocalDBPath string
	TransitiveScanningActions
}

type TransitiveScanningActions struct {
	Disabled         bool
	NativeDataSource bool
	MavenRegistry    string
}

// NoPackagesFoundErr for when no packages are found during a scan.
//
//nolint:errname,stylecheck,revive // Would require version major bump to change
var NoPackagesFoundErr = errors.New("no packages found in scan")

// VulnerabilitiesFoundErr includes both vulnerabilities being found or license violations being found,
// however, will not be raised if only uncalled vulnerabilities are found.
//
//nolint:errname,stylecheck,revive // Would require version major bump to change
var VulnerabilitiesFoundErr = errors.New("vulnerabilities found")

// Deprecated: This error is no longer returned, check the results to determine if this is the case
//
//nolint:errname,stylecheck,revive // Would require version bump to change
var OnlyUncalledVulnerabilitiesFoundErr = errors.New("only uncalled vulnerabilities found")

// ErrAPIFailed describes errors related to querying API endpoints.
var ErrAPIFailed = errors.New("API query failed")

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
func scanDir(r reporter.Reporter, dir string, skipGit bool, recursive bool, useGitIgnore bool, compareOffline bool, transitiveAct TransitiveScanningActions) ([]scannedPackage, error) {
	var ignoreMatcher *gitIgnoreMatcher
	if useGitIgnore {
		var err error
		ignoreMatcher, err = parseGitIgnores(dir, recursive)
		if err != nil {
			r.Errorf("Unable to parse git ignores: %v\n", err)
			useGitIgnore = false
		}
	}

	root := true

	var scannedPackages []scannedPackage

	return scannedPackages, filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			r.Infof("Failed to walk %s: %v\n", path, err)
			return err
		}

		path, err = filepath.Abs(path)
		if err != nil {
			r.Errorf("Failed to walk path %s\n", err)
			return err
		}

		if useGitIgnore {
			match, err := ignoreMatcher.match(path, info.IsDir())
			if err != nil {
				r.Infof("Failed to resolve gitignore for %s: %v\n", path, err)
				// Don't skip if we can't parse now - potentially noisy for directories with lots of items
			} else if match {
				if root { // Don't silently skip if the argument file was ignored.
					r.Errorf("%s was not scanned because it is excluded by a .gitignore file. Use --no-ignore to scan it.\n", path)
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
				r.Infof("scan failed for git repository, %s: %v\n", path, err)
				// Not fatal, so don't return and continue scanning other files
			}
			scannedPackages = append(scannedPackages, pkgs...)

			return filepath.SkipDir
		}

		if !info.IsDir() {
			pkgs, err := scanLockfile(r, path, "", transitiveAct)
			if err != nil {
				// If no extractors found then just continue
				if !errors.Is(err, lockfilescalibr.ErrNoExtractorsFound) {
					r.Errorf("Attempted to scan lockfile but failed: %s\n", path)
				}
			}
			scannedPackages = append(scannedPackages, pkgs...)

			// No need to check for error
			// If scan fails, it means it isn't a valid SBOM file,
			// so just move onto the next file
			pkgs, _ = scanSBOMFile(r, path, true)
			scannedPackages = append(scannedPackages, pkgs...)
		}

		if info.IsDir() && !compareOffline {
			if _, ok := vendoredLibNames[strings.ToLower(filepath.Base(path))]; ok {
				pkgs, err := scanDirWithVendoredLibs(r, path)
				if err != nil {
					r.Infof("scan failed for dir containing vendored libs %s: %v\n", path, err)
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

func parseGitIgnores(path string, recursive bool) (*gitIgnoreMatcher, error) {
	patterns, repoRootPath, err := customgitignore.ParseGitIgnores(path, recursive)
	if err != nil {
		return nil, err
	}

	matcher := gitignore.NewMatcher(patterns)

	return &gitIgnoreMatcher{matcher: matcher, repoPath: repoRootPath}, nil
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
	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, _ error) error {
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
	r.Infof("Scanning directory for vendored libs: %s\n", path)
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

		r.Infof("Scanning potential vendored dir: %s\n", libPath)
		// TODO: make this a goroutine to parallelise this operation
		results, err := queryDetermineVersions(libPath)
		if err != nil {
			r.Infof("Error scanning sub-directory '%s' with error: %v", libPath, err)
			continue
		}

		if len(results.Matches) > 0 && results.Matches[0].Score > determineVersionThreshold {
			match := results.Matches[0]
			r.Infof("Identified %s as %s at %s.\n", libPath, match.RepoInfo.Address, match.RepoInfo.Commit)
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

func scanImage(r reporter.Reporter, path string) ([]scannedPackage, error) {
	scanResults, err := image.ScanImage(r, path)
	if err != nil {
		return []scannedPackage{}, err
	}

	packages := make([]scannedPackage, 0)

	for _, l := range scanResults.Lockfiles {
		for _, pkgDetail := range l.Packages {
			packages = append(packages, scannedPackage{
				Name:        pkgDetail.Name,
				Version:     pkgDetail.Version,
				Commit:      pkgDetail.Commit,
				Ecosystem:   pkgDetail.Ecosystem,
				DepGroups:   pkgDetail.DepGroups,
				ImageOrigin: pkgDetail.ImageOrigin,
				Source: models.SourceInfo{
					Path: path + ":" + l.FilePath,
					Type: "docker",
				},
			})
		}
	}

	return packages, nil
}

// scanLockfile will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
func scanLockfile(r reporter.Reporter, path string, parseAs string, transitiveAct TransitiveScanningActions) ([]scannedPackage, error) {
	var err error

	var inventories []*extractor.Inventory

	// special case for the APK and DPKG parsers because they have a very generic name while
	// living at a specific location, so they are not included in the map of parsers
	// used by lockfile.Parse to avoid false-positives when scanning projects
	switch parseAs {
	case "apk-installed":
		inventories, err = lockfilescalibr.ExtractWithExtractor(context.Background(), path, apk.New(apk.DefaultConfig()))
	case "dpkg-status":
		inventories, err = lockfilescalibr.ExtractWithExtractor(context.Background(), path, dpkg.New(dpkg.DefaultConfig()))
	case "osv-scanner":
		inventories, err = lockfilescalibr.ExtractWithExtractor(context.Background(), path, osvscannerjson.Extractor{})
	default:
		if !transitiveAct.Disabled && (parseAs == "pom.xml" || filepath.Base(path) == "pom.xml") {
			ext, extErr := createMavenExtractor(transitiveAct)
			if extErr != nil {
				return nil, extErr
			}

			inventories, err = lockfilescalibr.ExtractWithExtractor(context.Background(), path, ext)
		} else {
			inventories, err = lockfilescalibr.Extract(context.Background(), path, parseAs)
		}
	}

	if err != nil {
		return nil, err
	}

	parsedAsComment := ""

	if parseAs != "" {
		parsedAsComment = fmt.Sprintf("as a %s ", parseAs)
	}

	slices.SortFunc(inventories, func(i, j *extractor.Inventory) int {
		return cmp.Or(
			strings.Compare(i.Name, j.Name),
			strings.Compare(i.Version, j.Version),
		)
	})

	pkgCount := len(inventories)

	r.Infof(
		"Scanned %s file %sand found %d %s\n",
		path,
		parsedAsComment,
		pkgCount,
		output.Form(pkgCount, "package", "packages"),
	)

	packages := make([]scannedPackage, 0, pkgCount)

	for _, inv := range inventories {
		scannedPackage := scannedPackage{
			Name:    inv.Name,
			Version: inv.Version,
			Source: models.SourceInfo{
				Path: path,
				Type: "lockfile",
			},
		}
		if inv.SourceCode != nil {
			scannedPackage.Commit = inv.SourceCode.Commit
		}
		eco := inv.Ecosystem()
		// TODO(rexpan): Refactor these minor patches to individual items
		// TODO: Ecosystem should be pared with Enum : Suffix
		if eco == "Alpine" {
			eco = "Alpine:v3.20"
		}

		scannedPackage.Ecosystem = lockfile.Ecosystem(eco)

		if dg, ok := inv.Metadata.(scalibrosv.DepGroups); ok {
			scannedPackage.DepGroups = dg.DepGroups()
		}

		packages = append(packages, scannedPackage)
	}

	return packages, nil
}

func createMavenExtractor(actions TransitiveScanningActions) (*pomxmlnet.Extractor, error) {
	var depClient client.DependencyClient
	var err error
	if actions.NativeDataSource {
		depClient, err = client.NewMavenRegistryClient(actions.MavenRegistry)
	} else {
		depClient, err = client.NewDepsDevClient(depsdev.DepsdevAPI)
	}
	if err != nil {
		return nil, err
	}

	mavenClient, err := datasource.NewMavenRegistryAPIClient(actions.MavenRegistry)
	if err != nil {
		return nil, err
	}

	extractor := pomxmlnet.Extractor{
		DependencyClient:       depClient,
		MavenRegistryAPIClient: mavenClient,
	}

	return &extractor, nil
}

// scanSBOMFile will load, identify, and parse the SBOM path passed in, and add the dependencies specified
// within to `query`
func scanSBOMFile(r reporter.Reporter, path string, fromFSScan bool) ([]scannedPackage, error) {
	var errs []error
	packages := map[string]scannedPackage{}
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

		var ignoredPURLs []string
		err = provider.GetPackages(file, func(id sbom.Identifier) error {
			_, err := models.PURLToPackage(id.PURL)
			if err != nil {
				ignoredPURLs = append(ignoredPURLs, id.PURL)
				//nolint:nilerr
				return nil
			}

			if _, ok := packages[id.PURL]; ok {
				r.Warnf("Warning, duplicate PURL found in SBOM: %s\n", id.PURL)
			}

			packages[id.PURL] = scannedPackage{
				PURL: id.PURL,
				Source: models.SourceInfo{
					Path: path,
					Type: "sbom",
				},
			}

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
			r.Infof(
				"Scanned %s as %s SBOM and found %d %s\n",
				path,
				provider.Name(),
				len(packages),
				output.Form(len(packages), "package", "packages"),
			)
			if len(ignoredPURLs) > 0 {
				r.Warnf(
					"Ignored %d %s with invalid PURLs\n",
					len(ignoredPURLs),
					output.Form(len(ignoredPURLs), "package", "packages"),
				)
				slices.Sort(ignoredPURLs)
				for _, purl := range slices.Compact(ignoredPURLs) {
					r.Warnf(
						"Ignored invalid PURL \"%s\"\n",
						purl,
					)
				}
			}

			sliceOfPackages := make([]scannedPackage, 0, len(packages))

			for _, pkg := range packages {
				sliceOfPackages = append(sliceOfPackages, pkg)
			}

			slices.SortFunc(sliceOfPackages, func(i, j scannedPackage) int {
				return strings.Compare(i.PURL, j.PURL)
			})

			return sliceOfPackages, nil
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
		r.Infof("Failed to parse SBOM using all supported formats:\n")
		for _, err := range errs {
			r.Infof("%s\n", err.Error())
		}
	}

	return nil, nil
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
	r.Infof("Scanning %s at commit %s\n", repoDir, commit)

	//nolint:prealloc // Not sure how many there will be in advance.
	var packages []scannedPackage
	packages = append(packages, createCommitQueryPackage(commit, repoDir))

	submodules, err := getSubmodules(repoDir)
	if err != nil {
		return nil, err
	}

	for _, s := range submodules {
		r.Infof("Scanning submodule %s at commit %s\n", s.Path, s.Expected.String())
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

func runCommandLogError(r reporter.Reporter, name string, args ...string) error {
	cmd := exec.Command(name, args...)

	// Get stderr for debugging when docker fails
	stderr, err := cmd.StderrPipe()
	if err != nil {
		r.Errorf("Failed to get stderr: %s\n", err)
		return err
	}

	err = cmd.Start()
	if err != nil {
		r.Errorf("Failed to run docker command (%q): %s\n", cmd.String(), err)
		return err
	}
	// This has to be captured before cmd.Wait() is called, as cmd.Wait() closes the stderr pipe.
	var stderrLines []string
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		stderrLines = append(stderrLines, scanner.Text())
	}

	err = cmd.Wait()
	if err != nil {
		r.Errorf("Docker command exited with code (%q): %d\nSTDERR:\n", cmd.String(), cmd.ProcessState.ExitCode())
		for _, line := range stderrLines {
			r.Errorf("> %s\n", line)
		}

		return errors.New("failed to run docker command")
	}

	return nil
}

func scanDockerImage(r reporter.Reporter, dockerImageName string) ([]scannedPackage, error) {
	tempImageFile, err := os.CreateTemp("", "docker-image-*.tar")
	if err != nil {
		r.Errorf("Failed to create temporary file: %s\n", err)
		return nil, err
	}

	err = tempImageFile.Close()
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempImageFile.Name())

	r.Infof("Pulling docker image (%q)...\n", dockerImageName)
	err = runCommandLogError(r, "docker", "pull", "-q", dockerImageName)
	if err != nil {
		return nil, err
	}

	r.Infof("Saving docker image (%q) to temporary file...\n", dockerImageName)
	err = runCommandLogError(r, "docker", "save", "-o", tempImageFile.Name(), dockerImageName)
	if err != nil {
		return nil, err
	}

	r.Infof("Scanning image...\n")
	packages, err := scanImage(r, tempImageFile.Name())
	if err != nil {
		return nil, err
	}

	// Modify the image path to be the image name, rather than the temporary file name
	for i := range packages {
		_, internalPath, _ := strings.Cut(packages[i].Source.Path, ":")
		packages[i].Source.Path = dockerImageName + ":" + internalPath
	}

	return packages, nil
}

// Filters results according to config, preserving order. Returns total number of vulnerabilities removed.
func filterResults(r reporter.Reporter, results *models.VulnerabilityResults, configManager *config.Manager, allPackages bool) int {
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
		for _, id := range group.Aliases {
			var ignoreLine config.IgnoreEntry
			if ignore, ignoreLine = configToUse.ShouldIgnore(id); ignore {
				for _, id := range group.Aliases {
					ignoredVulns[id] = struct{}{}
				}

				reason := ignoreLine.Reason

				if reason == "" {
					reason = "(no reason given)"
				}

				// NB: This only prints the first reason encountered in all the aliases.
				switch len(group.Aliases) {
				case 1:
					r.Infof("%s has been filtered out because: %s\n", ignoreLine.ID, reason)
				case 2:
					r.Infof("%s and 1 alias have been filtered out because: %s\n", ignoreLine.ID, reason)
				default:
					r.Infof("%s and %d aliases have been filtered out because: %s\n", ignoreLine.ID, len(group.Aliases)-1, reason)
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
	PURL        string
	Name        string
	Ecosystem   lockfile.Ecosystem
	Commit      string
	Version     string
	Source      models.SourceInfo
	ImageOrigin *models.ImageOriginDetails
	DepGroups   []string
}

// Perform osv scanner action, with optional reporter to output information
func DoScan(actions ScannerActions, r reporter.Reporter) (models.VulnerabilityResults, error) {
	if r == nil {
		r = &reporter.VoidReporter{}
	}

	if actions.CompareOffline {
		actions.SkipGit = true

		if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
			return models.VulnerabilityResults{}, errors.New("cannot retrieve licenses locally")
		}
	}

	if !actions.CompareOffline && actions.DownloadDatabases {
		return models.VulnerabilityResults{}, errors.New("databases can only be downloaded when running in offline mode")
	}

	configManager := config.Manager{
		DefaultConfig: config.Config{},
		ConfigMap:     make(map[string]config.Config),
	}

	//nolint:prealloc // Not sure how many there will be in advance.
	var scannedPackages []scannedPackage

	if actions.ConfigOverridePath != "" {
		err := configManager.UseOverride(r, actions.ConfigOverridePath)
		if err != nil {
			r.Errorf("Failed to read config file: %s\n", err)
			return models.VulnerabilityResults{}, err
		}
	}

	if actions.ExperimentalScannerActions.ScanOCIImage != "" {
		r.Infof("Scanning image %s\n", actions.ExperimentalScannerActions.ScanOCIImage)
		pkgs, err := scanImage(r, actions.ExperimentalScannerActions.ScanOCIImage)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}

		scannedPackages = append(scannedPackages, pkgs...)
	}

	if actions.DockerImageName != "" {
		pkgs, err := scanDockerImage(r, actions.DockerImageName)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	for _, lockfileElem := range actions.LockfilePaths {
		parseAs, lockfilePath := parseLockfilePath(lockfileElem)
		lockfilePath, err := filepath.Abs(lockfilePath)
		if err != nil {
			r.Errorf("Failed to resolved path with error %s\n", err)
			return models.VulnerabilityResults{}, err
		}
		pkgs, err := scanLockfile(r, lockfilePath, parseAs, actions.TransitiveScanningActions)
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
		r.Infof("Scanning dir %s\n", dir)
		pkgs, err := scanDir(r, dir, actions.SkipGit, actions.Recursive, !actions.NoIgnore, actions.CompareOffline, actions.TransitiveScanningActions)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	if len(scannedPackages) == 0 {
		return models.VulnerabilityResults{}, NoPackagesFoundErr
	}

	filteredScannedPackagesWithoutUnscannable := filterUnscannablePackages(scannedPackages)

	if len(filteredScannedPackagesWithoutUnscannable) != len(scannedPackages) {
		r.Infof("Filtered %d local package/s from the scan.\n", len(scannedPackages)-len(filteredScannedPackagesWithoutUnscannable))
	}

	filteredScannedPackages := filterIgnoredPackages(r, filteredScannedPackagesWithoutUnscannable, &configManager)

	if len(filteredScannedPackages) != len(filteredScannedPackagesWithoutUnscannable) {
		r.Infof("Filtered %d ignored package/s from the scan.\n", len(filteredScannedPackagesWithoutUnscannable)-len(filteredScannedPackages))
	}

	overrideGoVersion(r, filteredScannedPackages, &configManager)

	vulnsResp, err := makeRequest(r, filteredScannedPackages, actions.CompareOffline, actions.DownloadDatabases, actions.LocalDBPath)
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
	results := buildVulnerabilityResults(r, filteredScannedPackages, vulnsResp, licensesResp, actions, &configManager)

	filtered := filterResults(r, &results, &configManager, actions.ShowAllPackages)
	if filtered > 0 {
		r.Infof(
			"Filtered %d %s from output\n",
			filtered,
			output.Form(filtered, "vulnerability", "vulnerabilities"),
		)
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

		if (!vuln || onlyUncalledVuln) && !licenseViolation {
			// There is no error.
			return results, nil
		}

		return results, VulnerabilitiesFoundErr
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

// filterIgnoredPackages removes ignore scanned packages according to config. Returns filtered scanned packages.
func filterIgnoredPackages(r reporter.Reporter, packages []scannedPackage, configManager *config.Manager) []scannedPackage {
	out := make([]scannedPackage, 0, len(packages))
	for _, p := range packages {
		configToUse := configManager.Get(r, p.Source.Path)
		pkg := models.PackageVulns{
			Package: models.PackageInfo{
				Name:      p.Name,
				Version:   p.Version,
				Ecosystem: string(p.Ecosystem),
				Commit:    p.Commit,
			},
			DepGroups: p.DepGroups,
		}

		if ignore, ignoreLine := configToUse.ShouldIgnorePackage(pkg); ignore {
			var pkgString string
			if p.PURL != "" {
				pkgString = p.PURL
			} else {
				pkgString = fmt.Sprintf("%s/%s/%s", p.Ecosystem, p.Name, p.Version)
			}
			reason := ignoreLine.Reason

			if reason == "" {
				reason = "(no reason given)"
			}
			r.Infof("Package %s has been filtered out because: %s\n", pkgString, reason)

			continue
		}
		out = append(out, p)
	}

	return out
}

// patchPackageForRequest modifies packages before they are sent to osv.dev to
// account for edge cases.
func patchPackageForRequest(pkg scannedPackage) scannedPackage {
	// Assume Go stdlib patch version as the latest version
	//
	// This is done because go1.20 and earlier do not support patch
	// version in go.mod file, and will fail to build.
	//
	// However, if we assume patch version as .0, this will cause a lot of
	// false positives. This compromise still allows osv-scanner to pick up
	// when the user is using a minor version that is out-of-support.
	if pkg.Name == "stdlib" && pkg.Ecosystem == "Go" {
		v := semantic.ParseSemverLikeVersion(pkg.Version, 3)
		if len(v.Components) == 2 {
			pkg.Version = fmt.Sprintf(
				"%d.%d.%d",
				v.Components.Fetch(0),
				v.Components.Fetch(1),
				9999,
			)
		}
	}

	return pkg
}

func makeRequest(
	r reporter.Reporter,
	packages []scannedPackage,
	compareOffline bool,
	downloadDBs bool,
	localDBPath string) (*osv.HydratedBatchedResponse, error) {
	// Make OSV queries from the packages.
	var query osv.BatchedQuery
	for _, p := range packages {
		p = patchPackageForRequest(p)
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

	if compareOffline {
		// Downloading databases requires network access.
		hydratedResp, err := local.MakeRequest(r, query, !downloadDBs, localDBPath)
		if err != nil {
			return &osv.HydratedBatchedResponse{}, fmt.Errorf("local comparison failed %w", err)
		}

		return hydratedResp, nil
	}

	if osv.RequestUserAgent == "" {
		osv.RequestUserAgent = "osv-scanner-api_v" + version.OSVVersion
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("%w: osv.dev query failed: %w", ErrAPIFailed, err)
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("%w: failed to hydrate OSV response: %w", ErrAPIFailed, err)
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
		return nil, fmt.Errorf("%w: deps.dev query failed: %w", ErrAPIFailed, err)
	}

	return licenses, nil
}

// Overrides Go version using osv-scanner.toml
func overrideGoVersion(r reporter.Reporter, packages []scannedPackage, configManager *config.Manager) {
	for i, pkg := range packages {
		if pkg.Name == "stdlib" && pkg.Ecosystem == "Go" {
			configToUse := configManager.Get(r, pkg.Source.Path)
			if configToUse.GoVersionOverride != "" {
				packages[i].Version = configToUse.GoVersionOverride
			}

			continue
		}
	}
}
