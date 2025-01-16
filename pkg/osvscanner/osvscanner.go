package osvscanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scanner/internal/clients/clientimpl/baseimagematcher"
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
	"github.com/google/osv-scanner/pkg/osvscanner/internal/imagehelpers"
	"github.com/google/osv-scanner/pkg/osvscanner/internal/scanners"
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
	Image              string
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
	// Matchers
	VulnMatcher      clientinterfaces.VulnerabilityMatcher
	LicenseMatcher   clientinterfaces.LicenseMatcher
	BaseImageMatcher clientinterfaces.BaseImageMatcher

	// Required for pomxmlnet Extractor
	MavenRegistryAPIClient *datasource.MavenRegistryAPIClient
	// Required for vendored Extractor
	OSVDevClient *osvdev.OSVClient

	// DependencyClients is a map of implementations of DependencyClient
	// for each ecosystem, the following is currently implemented:
	// - [osvschema.EcosystemMaven] required for pomxmlnet Extractor
	DependencyClients map[osvschema.Ecosystem]client.DependencyClient
}

// ErrNoPackagesFound for when no packages are found during a scan.
var ErrNoPackagesFound = errors.New("no packages found in scan")

// ErrVulnerabilitiesFound includes both vulnerabilities being found or license violations being found,
// however, will not be raised if only uncalled vulnerabilities are found.
var ErrVulnerabilitiesFound = errors.New("vulnerabilities found")

// ErrAPIFailed describes errors related to querying API endpoints.
var ErrAPIFailed = errors.New("API query failed")

func initializeExternalAccessors(r reporter.Reporter, actions ScannerActions) (ExternalAccessors, error) {
	externalAccessors := ExternalAccessors{
		DependencyClients: map[osvschema.Ecosystem]client.DependencyClient{},
	}
	var err error

	// Offline Mode
	// ------------
	if actions.CompareOffline {
		// --- Vulnerability Matcher ---
		externalAccessors.VulnMatcher, err = localmatcher.NewLocalMatcher(r, actions.LocalDBPath, "osv-scanner_scan/"+version.OSVVersion, actions.DownloadDatabases)
		if err != nil {
			return ExternalAccessors{}, err
		}

		return externalAccessors, nil
	}

	// Online Mode
	// -----------
	// --- Vulnerability Matcher ---
	externalAccessors.VulnMatcher = &osvmatcher.OSVMatcher{
		Client:              *osvdev.DefaultClient(),
		InitialQueryTimeout: 5 * time.Minute,
	}

	// --- License Matcher ---
	if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
		depsDevAPIClient, err := datasource.NewDepsDevAPIClient(depsdev.DepsdevAPI, "osv-scanner_scan/"+version.OSVVersion)
		if err != nil {
			return ExternalAccessors{}, err
		}

		externalAccessors.LicenseMatcher = &licensematcher.DepsDevLicenseMatcher{
			Client: depsDevAPIClient,
		}
	}

	// --- Base Image Matcher ---
	if actions.Image != "" || actions.ScanOCIImage != "" {
		externalAccessors.BaseImageMatcher = &baseimagematcher.DepsDevBaseImageMatcher{
			Client: *http.DefaultClient,
		}
	}

	// --- OSV.dev Client ---
	// We create a separate client from VulnMatcher to keep things clean.
	externalAccessors.OSVDevClient = osvdev.DefaultClient()

	// --- No Transitive Scanning ---
	if actions.TransitiveScanningActions.Disabled {
		return externalAccessors, nil
	}

	// --- Transitive Scanning Clients ---
	externalAccessors.MavenRegistryAPIClient, err = datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{
		URL:             actions.TransitiveScanningActions.MavenRegistry,
		ReleasesEnabled: true,
	})

	if err != nil {
		return ExternalAccessors{}, err
	}

	if !actions.TransitiveScanningActions.NativeDataSource {
		externalAccessors.DependencyClients[osvschema.EcosystemMaven], err = client.NewDepsDevClient(depsdev.DepsdevAPI, "osv-scanner_scan/"+version.OSVVersion)
	} else {
		externalAccessors.DependencyClients[osvschema.EcosystemMaven], err = client.NewMavenRegistryClient(actions.TransitiveScanningActions.MavenRegistry)
	}

	if err != nil {
		return ExternalAccessors{}, err
	}

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
	accessors, err := initializeExternalAccessors(r, actions)
	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("failed to initialize accessors: %w", err)
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

	return results, determineReturnErr(results)
}

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

	// --- Setup Accessors/Clients ---
	accessors, err := initializeExternalAccessors(r, actions)
	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("failed to initialize accessors: %v", err)
	}

	// --- Initialize Image To Scan ---
	var img *image.Image
	if actions.ScanOCIImage != "" {
		img, err = image.FromTarball(actions.ScanOCIImage, image.DefaultConfig())
		r.Infof("Scanning image %q\n", actions.ScanOCIImage)
	} else if actions.Image != "" {
		path, exportErr := imagehelpers.ExportDockerImage(r, actions.Image)
		if exportErr != nil {
			return models.VulnerabilityResults{}, exportErr
		}

		// If Image is a local tar file, then path == Image, and we shouldn't remove it
		if path != actions.Image {
			defer os.Remove(path)
		}
		img, err = image.FromTarball(path, image.DefaultConfig())
		r.Infof("Scanning image %q\n", actions.Image)
	}
	if err != nil {
		return models.VulnerabilityResults{}, err
	}
	defer img.CleanUp()

	scanner := scalibr.New()
	scalibrSR, err := scanner.ScanContainer(context.Background(), img, &scalibr.ScanConfig{
		FilesystemExtractors: scanners.BuildArtifactExtractors(),
	})

	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("failed to scan container image: %w", err)
	}

	if len(scalibrSR.Inventories) == 0 {
		return models.VulnerabilityResults{}, ErrNoPackagesFound
	}

	// --- Fill Image Metadata ---
	{
		chainLayers, err := img.ChainLayers()
		if err != nil {
			// This is very unlikely, as if this would error we would have failed the initial scan
			return models.VulnerabilityResults{}, err
		}
		m, err := osrelease.GetOSRelease(chainLayers[len(chainLayers)-1].FS())
		OS := "Unknown"
		if err == nil {
			OS = m["PRETTY_NAME"]
		}

		scanResult.PackageScanResults = make([]imodels.PackageScanResult, len(scalibrSR.Inventories))
		for i, inv := range scalibrSR.Inventories {
			scanResult.PackageScanResults[i].PackageInfo = imodels.FromInventory(inv)
			scanResult.PackageScanResults[i].LayerDetails = inv.LayerDetails
		}

		layerMetadata := []models.LayerMetadata{}
		for _, cl := range chainLayers {
			layerMetadata = append(layerMetadata, models.LayerMetadata{
				DiffID:  cl.Layer().DiffID(),
				Command: cl.Layer().Command(),
				IsEmpty: cl.Layer().IsEmpty(),
			})
		}

		scanResult.ImageMetadata = &models.ImageMetadata{
			OS:            OS,
			LayerMetadata: layerMetadata,
		}

		if accessors.BaseImageMatcher != nil {
			scanResult.ImageMetadata.BaseImages, err = accessors.BaseImageMatcher.MatchBaseImages(context.Background(), layerMetadata)
			if err != nil {
				return models.VulnerabilityResults{}, fmt.Errorf("failed to query for container base images: %w", err)
			}
		} else {
			scanResult.ImageMetadata.BaseImages = [][]models.BaseImageDetails{
				// The base image at index 0 is a placeholder representing your image, so always empty
				// This is the case even if your image is a base image, in that case no layers point to index 0
				{},
			}
		}
	}

	// ----- Filtering -----
	filterUnscannablePackages(r, &scanResult)

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

	return results, determineReturnErr(results)
}

// determineReturnErr determines whether we found a "vulnerability" or not,
// and therefore whether we should return a ErrVulnerabilityFound error.
func determineReturnErr(results models.VulnerabilityResults) error {
	if len(results.Results) > 0 {
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

		if (!vuln || onlyUncalledVuln) && !licenseViolation {
			// There is no error.
			return nil
		}

		return ErrVulnerabilitiesFound
	}

	return nil
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
