package osvscanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scanner/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/internal/clients/clientimpl/osvmatcher"
	"github.com/google/osv-scanner/internal/clients/clientinterfaces"
	"github.com/google/osv-scanner/internal/config"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/imodels/results"
	"github.com/google/osv-scanner/internal/osvdev"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/opencontainers/go-digest"
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
		r.Infof("Scanning image %q\n", actions.DockerImageName)
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

	// --- Fill Image Metadata ---
	{
		// Ignore error, as if this would error we would have failed the initial scan
		chainLayers, _ := img.ChainLayers()
		m, err := osrelease.GetOSRelease(chainLayers[len(chainLayers)-1].FS())
		OS := "Unknown"
		if err != nil {
			OS = m["OSID"]
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
			BaseImages: [][]models.BaseImageDetails{
				// The base image at index 0 is a placeholder representing your image, so always empty
				// This is the case even if your image is a base image, in that case no layers point to index 0
				{},
			},
			OS:            OS,
			LayerMetadata: layerMetadata,
		}

		var runningDigest digest.Digest
		chainIDs := []digest.Digest{}

		for _, cl := range chainLayers {
			var diffDigest digest.Digest
			if cl.Layer().DiffID() == "" {
				chainIDs = append(chainIDs, "")
				continue
			}

			diffDigest = digest.NewDigestFromEncoded(digest.SHA256, cl.Layer().DiffID())

			if runningDigest == "" {
				runningDigest = diffDigest
			} else {
				runningDigest = digest.FromBytes([]byte(runningDigest + " " + diffDigest))
			}

			chainIDs = append(chainIDs, runningDigest)
		}

		currentBaseImageIndex := 0
		client := http.DefaultClient
		for i, cid := range slices.Backward(chainIDs) {
			if cid == "" {
				scanResult.ImageMetadata.LayerMetadata[i].BaseImageIndex = currentBaseImageIndex
				continue
			}

			resp, err := client.Get("https://api.deps.dev/v3alpha/querycontainerimages/" + cid.String())
			if err != nil {
				log.Errorf("API DEPS DEV ERROR: %s", err)
				continue
			}

			if resp.StatusCode == http.StatusNotFound {
				scanResult.ImageMetadata.LayerMetadata[i].BaseImageIndex = currentBaseImageIndex
				continue
			}

			if resp.StatusCode != http.StatusOK {
				log.Errorf("API DEPS DEV ERROR: %s", resp.Status)
				continue
			}

			d := json.NewDecoder(resp.Body)

			type baseImageEntry struct {
				Repository string `json:"repository"`
			}
			type baseImageResults struct {
				Results []baseImageEntry `json:"results"`
			}

			var results baseImageResults
			err = d.Decode(&results)
			if err != nil {
				log.Errorf("API DEPS DEV ERROR: %s", err)
				continue
			}

			// Found some base images!
			baseImagePossibilities := []models.BaseImageDetails{}
			for _, r := range results.Results {
				baseImagePossibilities = append(baseImagePossibilities, models.BaseImageDetails{
					Name: r.Repository,
				})
			}

			slices.SortFunc(baseImagePossibilities, func(a, b models.BaseImageDetails) int {
				return len(a.Name) - len(b.Name)
			})

			scanResult.ImageMetadata.BaseImages = append(scanResult.ImageMetadata.BaseImages, baseImagePossibilities)
			currentBaseImageIndex += 1
			scanResult.ImageMetadata.LayerMetadata[i].BaseImageIndex = currentBaseImageIndex

			// Backfill with heuristic

			possibleFinalBaseImageCommands := []string{
				"/bin/sh -c #(nop)  CMD",
				"CMD",
				"/bin/sh -c #(nop)  ENTRYPOINT",
				"ENTRYPOINT",
			}
		BackfillLoop:
			for i2 := i; i2 < len(scanResult.ImageMetadata.LayerMetadata); i2++ {
				if !scanResult.ImageMetadata.LayerMetadata[i2].IsEmpty {
					break
				}
				buildCommand := scanResult.ImageMetadata.LayerMetadata[i2].Command
				scanResult.ImageMetadata.LayerMetadata[i2].BaseImageIndex = currentBaseImageIndex
				for _, prefix := range possibleFinalBaseImageCommands {
					if strings.HasPrefix(buildCommand, prefix) {
						break BackfillLoop
					}
				}
			}

		}
	}

	// ----- Filtering -----
	filterUnscannablePackages(r, &scanResult)

	// --- Make Vulnerability Requests ---
	{
		var matcher clientinterfaces.VulnerabilityMatcher
		var err error
		if actions.CompareOffline {
			matcher, err = localmatcher.NewLocalMatcher(r, actions.LocalDBPath, actions.DownloadDatabases)
			if err != nil {
				return models.VulnerabilityResults{}, err
			}
		} else {
			matcher = &osvmatcher.OSVMatcher{
				Client:              *osvdev.DefaultClient(),
				InitialQueryTimeout: 5 * time.Minute,
			}
		}

		err = makeRequestWithMatcher(r, scanResult.PackageScanResults, matcher)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
	}

	if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
		err = makeLicensesRequests(scanResult.PackageScanResults)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
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
	// Skip saving if the file is already a tar archive.
	if strings.Contains(dockerImageName, ".tar") {
		if _, err := os.Stat(dockerImageName); err == nil {
			return dockerImageName, nil
		}
	}

	tempImageFile, err := os.CreateTemp("", "docker-image-*.tar")
	if err != nil {
		r.Errorf("Failed to create temporary file: %s\n", err)
		return "", err
	}

	err = tempImageFile.Close()
	if err != nil {
		return "", err
	}

	// Check if image exists locally, if not, pull from the cloud.
	r.Infof("Checking if docker image (%q) exists locally...\n", dockerImageName)
	cmd := exec.Command("docker", "images", "-q", dockerImageName)
	output, err := cmd.Output()
	if err != nil || string(output) == "" {
		r.Infof("Image not found locally, pulling docker image (%q)...\n", dockerImageName)
		err = runCommandLogError(r, "docker", "pull", "-q", dockerImageName)
		if err != nil {
			return "", fmt.Errorf("failed to pull container image: %w", err)
		}
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

	// ----- Filtering -----
	filterUnscannablePackages(r, &scanResult)
	filterIgnoredPackages(r, &scanResult)

	// ----- Custom Overrides -----
	overrideGoVersion(r, &scanResult)

	// --- Make Vulnerability Requests ---
	{
		var matcher clientinterfaces.VulnerabilityMatcher
		var err error
		if actions.CompareOffline {
			matcher, err = localmatcher.NewLocalMatcher(r, actions.LocalDBPath, actions.DownloadDatabases)
			if err != nil {
				return models.VulnerabilityResults{}, err
			}
		} else {
			matcher = &osvmatcher.OSVMatcher{
				Client:              *osvdev.DefaultClient(),
				InitialQueryTimeout: 5 * time.Minute,
			}
		}

		err = makeRequestWithMatcher(r, scanResult.PackageScanResults, matcher)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
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

// TODO(V2): Add context
func makeRequestWithMatcher(
	r reporter.Reporter,
	packages []imodels.PackageScanResult,
	matcher clientinterfaces.VulnerabilityMatcher) error {
	invs := make([]*extractor.Inventory, 0, len(packages))
	for _, pkgs := range packages {
		invs = append(invs, pkgs.PackageInfo.Inventory)
	}

	res, err := matcher.MatchVulnerabilities(context.Background(), invs)
	if err != nil {
		// TODO: Handle error here
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

// TODO(V2): Replace with client
func makeLicensesRequests(packages []imodels.PackageScanResult) error {
	queries := make([]*depsdevpb.GetVersionRequest, len(packages))
	for i, psr := range packages {
		pkg := psr.PackageInfo
		system, ok := depsdev.System[psr.PackageInfo.Ecosystem().Ecosystem]
		if !ok || pkg.Name() == "" || pkg.Version() == "" {
			continue
		}
		queries[i] = depsdev.VersionQuery(system, pkg.Name(), pkg.Version())
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
		if pkg.Name() == "stdlib" && pkg.Ecosystem().Ecosystem == osvschema.EcosystemGo {
			configToUse := scanResults.ConfigManager.Get(r, pkg.Location())
			if configToUse.GoVersionOverride != "" {
				scanResults.PackageScanResults[i].PackageInfo.Inventory.Version = configToUse.GoVersionOverride
			}

			continue
		}
	}
}
