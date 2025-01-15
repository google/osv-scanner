package osvscanner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/internal/clients/clientimpl/licensematcher"
	"github.com/google/osv-scanner/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/internal/clients/clientimpl/osvmatcher"
	"github.com/google/osv-scanner/internal/clients/clientinterfaces"
	"github.com/google/osv-scanner/internal/config"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/imodels/results"
	"github.com/google/osv-scanner/internal/osvdev"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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

type ExternalAccessors struct {
	VulnMatcher            clientinterfaces.VulnerabilityMatcher
	LicenseMatcher         clientinterfaces.LicenseMatcher
	MavenRegistryAPIClient *datasource.MavenRegistryAPIClient
	OSVDevClient           *osvdev.OSVClient
	DependencyClients      map[osvschema.Ecosystem]client.DependencyClient
}

// ErrNoPackagesFound for when no packages are found during a scan.
var ErrNoPackagesFound = errors.New("no packages found in scan")

// ErrVulnerabilitiesFound includes both vulnerabilities being found or license violations being found,
// however, will not be raised if only uncalled vulnerabilities are found.
var ErrVulnerabilitiesFound = errors.New("vulnerabilities found")

// ErrAPIFailed describes errors related to querying API endpoints.
var ErrAPIFailed = errors.New("API query failed")

func InitializeExternalAccessors(r reporter.Reporter, actions ScannerActions) (ExternalAccessors, error) {
	externalAccessors := ExternalAccessors{
		DependencyClients: map[osvschema.Ecosystem]client.DependencyClient{},
	}

	// --- Vulnerability Matcher ---
	var err error
	if actions.CompareOffline {
		externalAccessors.VulnMatcher, err = localmatcher.NewLocalMatcher(r, actions.LocalDBPath, "osv-scanner_scan/"+version.OSVVersion, actions.DownloadDatabases)
		if err != nil {
			return ExternalAccessors{}, err
		}

		return externalAccessors, nil
	}

	// Not offline, so create accessors that require network access
	externalAccessors.VulnMatcher = &osvmatcher.OSVMatcher{
		Client:              *osvdev.DefaultClient(),
		InitialQueryTimeout: 5 * time.Minute,
	}

	// --- License Matcher ---
	depsdevapiclient, err := datasource.NewDepsDevAPIClient(depsdev.DepsdevAPI, "osv-scanner_scan/"+version.OSVVersion)
	if err != nil {
		return ExternalAccessors{}, err
	}

	if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
		externalAccessors.LicenseMatcher = &licensematcher.DepsDevLicenseMatcher{
			Client: depsdevapiclient,
		}
	}

	if actions.TransitiveScanningActions.Disabled {
		return externalAccessors, nil
	}

	externalAccessors.MavenRegistryAPIClient, err = datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{
		URL:             actions.TransitiveScanningActions.MavenRegistry,
		ReleasesEnabled: true,
	})

	if err != nil {
		return ExternalAccessors{}, err
	}

	if !actions.TransitiveScanningActions.NativeDataSource {
		depsDevAPIClient, _ := client.NewDepsDevClient(depsdev.DepsdevAPI, "osv-scanner_scan/"+version.OSVVersion)
		externalAccessors.DependencyClients[osvschema.EcosystemMaven] = depsDevAPIClient
	} else {
		externalAccessors.DependencyClients[osvschema.EcosystemMaven], err = client.NewMavenRegistryClient(actions.TransitiveScanningActions.MavenRegistry)
		if err != nil {
			return ExternalAccessors{}, err
		}
	}

	externalAccessors.OSVDevClient = osvdev.DefaultClient()

	return externalAccessors, nil
}

// Perform osv scanner action, with optional reporter to output information
func DoScan(actions ScannerActions, r reporter.Reporter) (models.VulnerabilityResults, error) {
	if r == nil {
		r = &reporter.VoidReporter{}
	}

	// --- Sanity check flags ----
	// TODO(v2): Move the logic of the offline flag changing other flags into here from the main.go/scan.go
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

	// --- Setup Config ---
	if actions.ConfigOverridePath != "" {
		err := scanResult.ConfigManager.UseOverride(r, actions.ConfigOverridePath)
		if err != nil {
			r.Errorf("Failed to read config file: %s\n", err)
			return models.VulnerabilityResults{}, err
		}
	}

	// --- Setup Accessors/Clients ---
	accessors, err := InitializeExternalAccessors(r, actions)
	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("failed to initialize accessors: %v", err)
	}

	// ----- Perform Scanning -----
	packages, err := scan(r, accessors, actions)
	if err != nil {
		return models.VulnerabilityResults{}, err
	}

	scanResult.PackageScanResults = packages

	// ----- Filtering -----
	filterUnscannablePackages(r, &scanResult)
	filterIgnoredPackages(r, &scanResult)

	// ----- Custom Overrides -----
	overrideGoVersion(r, &scanResult)

	// --- Make Vulnerability Requests ---
	if accessors.VulnMatcher != nil {
		err = makeVulnRequestWithMatcher(r, scanResult.PackageScanResults, accessors.VulnMatcher)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	// --- Make License Requests ---
	if accessors.LicenseMatcher != nil {
		err = accessors.LicenseMatcher.MatchLicenses(context.Background(), scanResult.PackageScanResults)
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

		return results, ErrVulnerabilitiesFound
	}

	return results, nil
}

// TODO(V2): Add context
func makeVulnRequestWithMatcher(
	r reporter.Reporter,
	packages []imodels.PackageScanResult,
	matcher clientinterfaces.VulnerabilityMatcher) error {
	invs := make([]*extractor.Inventory, 0, len(packages))
	for _, pkgs := range packages {
		invs = append(invs, pkgs.PackageInfo.Inventory)
	}

	res, err := matcher.MatchVulnerabilities(context.Background(), invs)
	if err != nil {
		r.Errorf("error when retrieving vulns: %v", err)
		if res == nil {
			return err
		}
	}

	for i, vulns := range res {
		packages[i].Vulnerabilities = vulns
	}

	return nil
}

// Overrides Go version using osv-scanner.toml
func overrideGoVersion(r reporter.Reporter, scanResults *results.ScanResults) {
	for i, psr := range scanResults.PackageScanResults {
		pkg := psr.PackageInfo
		if pkg.Name() == "stdlib" && pkg.Ecosystem().Ecosystem == osvschema.EcosystemGo {
			configToUse := scanResults.ConfigManager.Get(r, pkg.Location())
			if configToUse.GoVersionOverride != "" {
				scanResults.PackageScanResults[i].PackageInfo.Inventory.Version = configToUse.GoVersionOverride
			}

			continue
		}
	}
}
