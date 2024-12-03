package osvscanner

import (
	//nolint:gosec
	"errors"
	"fmt"

	"github.com/google/osv-scanner/internal/config"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/local"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/pomxmlnet"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/reporter"

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

	if actions.ConfigOverridePath != "" {
		err := configManager.UseOverride(r, actions.ConfigOverridePath)
		if err != nil {
			r.Errorf("Failed to read config file: %s\n", err)
			return models.VulnerabilityResults{}, err
		}
	}

	// Perform each individual scan action specified in actions
	scannedPackages, err := scan(r, actions)
	if err != nil {
		return models.VulnerabilityResults{}, err
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

// patchPackageForRequest modifies packages before they are sent to osv.dev to
// account for edge cases.
func patchPackageForRequest(pkg imodels.ScannedPackage) imodels.ScannedPackage {
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
	packages []imodels.ScannedPackage,
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
		osv.RequestUserAgent = "osv-scanner-api/v" + version.OSVVersion
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

func makeLicensesRequests(packages []imodels.ScannedPackage) ([][]models.License, error) {
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
func overrideGoVersion(r reporter.Reporter, packages []imodels.ScannedPackage, configManager *config.Manager) {
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
