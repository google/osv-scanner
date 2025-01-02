package osvscanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scanner/internal/config"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/imodels/results"
	"github.com/google/osv-scanner/internal/local"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	scalibr "github.com/google/osv-scalibr"

	depsdevpb "deps.dev/api/v3"
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

func DoContainerScan(actions ScannerActions, r reporter.Reporter) (models.VulnerabilityResults, error) {
	if r == nil {
		r = &reporter.VoidReporter{}
	}

	scanResult := results.ScanResults{
		ConfigManager: config.Manager{
			DefaultConfig: config.Config{},
			ConfigMap:     make(map[string]config.Config),
		},
	}

	scanner := scalibr.New()

	var img *image.Image
	var err error
	if actions.ScanOCIImage != "" {
		img, err = image.FromTarball(actions.ScanOCIImage, image.DefaultConfig())
		r.Infof("Scanning image %q\n", actions.ScanOCIImage)
	} else if actions.DockerImageName != "" {
		path, exportErr := exportDockerImage(r, actions.DockerImageName)
		if exportErr != nil {
			return models.VulnerabilityResults{}, exportErr
		}
		defer os.Remove(path)
		img, err = image.FromTarball(path, image.DefaultConfig())
		r.Infof("Scanning image %q\n", path)
	}
	if err != nil {
		return models.VulnerabilityResults{}, err
	}
	defer img.CleanUp()

	scalibrSR, err := scanner.ScanContainer(context.Background(), img, &scalibr.ScanConfig{
		FilesystemExtractors: []filesystem.Extractor{
			nodemodules.Extractor{},
			apk.New(apk.DefaultConfig()),
			gobinary.New(gobinary.DefaultConfig()),
			// TODO: Add tests for debian containers
			dpkg.New(dpkg.DefaultConfig()),
		},
	})

	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("failed to scan container image: %w", err)
	}

	if len(scalibrSR.Inventories) == 0 {
		return models.VulnerabilityResults{}, NoPackagesFoundErr
	}

	scanResult.PackageScanResults = make([]imodels.PackageScanResult, len(scalibrSR.Inventories))
	for i, inv := range scalibrSR.Inventories {
		scanResult.PackageScanResults[i].PackageInfo = imodels.FromInventory(inv)
		scanResult.PackageScanResults[i].LayerDetails = inv.LayerDetails
	}

	filterUnscannablePackages(r, &scanResult)

	err = makeRequest(r, scanResult.PackageScanResults, actions.CompareOffline, actions.DownloadDatabases, actions.LocalDBPath)
	if err != nil {
		return models.VulnerabilityResults{}, err
	}

	if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
		err = makeLicensesRequests(scanResult.PackageScanResults)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	results := buildVulnerabilityResults(r, actions, &scanResult)

	filtered := filterResults(r, &results, &scanResult.ConfigManager, actions.ShowAllPackages)
	if filtered > 0 {
		r.Infof(
			"Filtered %d %s from output\n",
			filtered,
			output.Form(filtered, "vulnerability", "vulnerabilities"),
		)
	}

	if len(results.Results) > 0 {
		// Determine the correct error to return.

		// TODO(v2): in the next breaking release of osv-scanner, consider
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

func exportDockerImage(r reporter.Reporter, dockerImageName string) (string, error) {
	tempImageFile, err := os.CreateTemp("", "docker-image-*.tar")
	if err != nil {
		r.Errorf("Failed to create temporary file: %s\n", err)
		return "", err
	}

	err = tempImageFile.Close()
	if err != nil {
		return "", err
	}

	r.Infof("Pulling docker image (%q)...\n", dockerImageName)
	err = runCommandLogError(r, "docker", "pull", "-q", dockerImageName)
	if err != nil {
		return "", fmt.Errorf("failed to pull container image: %w", err)
	}

	r.Infof("Saving docker image (%q) to temporary file...\n", dockerImageName)
	err = runCommandLogError(r, "docker", "save", "-o", tempImageFile.Name(), dockerImageName)
	if err != nil {
		return "", err
	}

	return tempImageFile.Name(), nil
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

// Perform osv scanner action, with optional reporter to output information
func DoScan(actions ScannerActions, r reporter.Reporter) (models.VulnerabilityResults, error) {
	if r == nil {
		r = &reporter.VoidReporter{}
	}

	// TODO(v2): Move the logic of the offline flag moving other flags into here.
	if actions.CompareOffline {
		actions.SkipGit = true

		if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
			return models.VulnerabilityResults{}, errors.New("cannot retrieve licenses locally")
		}
	}

	if !actions.CompareOffline && actions.DownloadDatabases {
		return models.VulnerabilityResults{}, errors.New("databases can only be downloaded when running in offline mode")
	}

	scanResult := results.ScanResults{
		ConfigManager: config.Manager{
			DefaultConfig: config.Config{},
			ConfigMap:     make(map[string]config.Config),
		},
	}

	if actions.ConfigOverridePath != "" {
		err := scanResult.ConfigManager.UseOverride(r, actions.ConfigOverridePath)
		if err != nil {
			r.Errorf("Failed to read config file: %s\n", err)
			return models.VulnerabilityResults{}, err
		}
	}

	// ----- Perform Scanning -----
	packages, err := scan(r, actions)
	if err != nil {
		return models.VulnerabilityResults{}, err
	}

	scanResult.PackageScanResults = packages

	filterUnscannablePackages(r, &scanResult)

	filterIgnoredPackages(r, &scanResult)

	overrideGoVersion(r, &scanResult)

	err = makeRequest(r, scanResult.PackageScanResults, actions.CompareOffline, actions.DownloadDatabases, actions.LocalDBPath)
	if err != nil {
		return models.VulnerabilityResults{}, err
	}

	if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
		err = makeLicensesRequests(scanResult.PackageScanResults)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	results := buildVulnerabilityResults(r, actions, &scanResult)

	filtered := filterResults(r, &results, &scanResult.ConfigManager, actions.ShowAllPackages)
	if filtered > 0 {
		r.Infof(
			"Filtered %d %s from output\n",
			filtered,
			output.Form(filtered, "vulnerability", "vulnerabilities"),
		)
	}

	if len(results.Results) > 0 {
		// Determine the correct error to return.

		// TODO(v2): in the next breaking release of osv-scanner, consider
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

// patchPackageForRequest modifies packages before they are sent to osv.dev to
// account for edge cases.
func patchPackageForRequest(pkg imodels.PackageInfo) imodels.PackageInfo {
	// Assume Go stdlib patch version as the latest version
	//
	// This is done because go1.20 and earlier do not support patch
	// version in go.mod file, and will fail to build.
	//
	// However, if we assume patch version as .0, this will cause a lot of
	// false positives. This compromise still allows osv-scanner to pick up
	// when the user is using a minor version that is out-of-support.
	if pkg.Name == "stdlib" && pkg.Ecosystem.Ecosystem == osvschema.EcosystemGo {
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

// TODO(V2): This will be replaced by the new client interface
func makeRequest(
	r reporter.Reporter,
	packages []imodels.PackageScanResult,
	compareOffline bool,
	downloadDBs bool,
	localDBPath string) error {
	// Make OSV queries from the packages.
	var query osv.BatchedQuery
	for _, psr := range packages {
		p := psr.PackageInfo
		p = patchPackageForRequest(p)
		switch {
		// Prefer making package requests where possible.
		case !p.Ecosystem.IsEmpty() && p.Name != "" && p.Version != "":
			query.Queries = append(query.Queries, osv.MakePkgRequest(p))
		case p.Commit != "":
			query.Queries = append(query.Queries, osv.MakeCommitRequest(p.Commit))
		default:
			return fmt.Errorf("package %v does not have a commit, PURL or ecosystem/name/version identifier", p)
		}
	}
	var err error
	var hydratedResp *osv.HydratedBatchedResponse

	if compareOffline {
		// TODO(v2): Stop depending on lockfile.PackageDetails and use imodels.PackageInfo
		// Downloading databases requires network access.
		hydratedResp, err = local.MakeRequest(r, query, !downloadDBs, localDBPath)
		if err != nil {
			return fmt.Errorf("local comparison failed %w", err)
		}
	} else {
		if osv.RequestUserAgent == "" {
			osv.RequestUserAgent = "osv-scanner-api/v" + version.OSVVersion
		}

		resp, err := osv.MakeRequest(query)
		if err != nil {
			return fmt.Errorf("%w: osv.dev query failed: %w", ErrAPIFailed, err)
		}

		hydratedResp, err = osv.Hydrate(resp)
		if err != nil {
			return fmt.Errorf("%w: failed to hydrate OSV response: %w", ErrAPIFailed, err)
		}
	}

	for i, result := range hydratedResp.Results {
		packages[i].Vulnerabilities = result.Vulns
	}

	return nil
}

// TODO(V2): Replace with client
func makeLicensesRequests(packages []imodels.PackageScanResult) error {
	queries := make([]*depsdevpb.GetVersionRequest, len(packages))
	for i, psr := range packages {
		pkg := psr.PackageInfo
		system, ok := depsdev.System[psr.PackageInfo.Ecosystem.Ecosystem]
		if !ok || pkg.Name == "" || pkg.Version == "" {
			continue
		}
		queries[i] = depsdev.VersionQuery(system, pkg.Name, pkg.Version)
	}
	licenses, err := depsdev.MakeVersionRequests(queries)
	if err != nil {
		return fmt.Errorf("%w: deps.dev query failed: %w", ErrAPIFailed, err)
	}

	for i, license := range licenses {
		packages[i].Licenses = license
	}

	return nil
}

// Overrides Go version using osv-scanner.toml
func overrideGoVersion(r reporter.Reporter, scanResults *results.ScanResults) {
	for i, psr := range scanResults.PackageScanResults {
		pkg := psr.PackageInfo
		if pkg.Name == "stdlib" && pkg.Ecosystem.Ecosystem == osvschema.EcosystemGo {
			configToUse := scanResults.ConfigManager.Get(r, pkg.Location)
			if configToUse.GoVersionOverride != "" {
				scanResults.PackageScanResults[i].PackageInfo.Version = configToUse.GoVersionOverride
			}

			continue
		}
	}
}
