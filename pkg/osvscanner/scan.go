package osvscanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirementsnet"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func configurePlugins(extractors []plugin.Plugin, accessors ExternalAccessors, actions ScannerActions) {
	for _, tor := range extractors {
		if accessors.DependencyClients[osvschema.EcosystemMaven] != nil && accessors.MavenRegistryAPIClient != nil {
			pomxmlenhanceable.EnhanceIfPossible(tor, pomxmlnet.Config{
				DependencyClient:       accessors.DependencyClients[osvschema.EcosystemMaven],
				MavenRegistryAPIClient: accessors.MavenRegistryAPIClient,
			})
		}
		if accessors.DependencyClients[osvschema.EcosystemPyPI] != nil {
			requirementsenhancable.EnhanceIfPossible(tor, requirementsnet.Config{
				Extractor: &requirements.Extractor{},
				Client:    accessors.DependencyClients[osvschema.EcosystemPyPI],
			})
		}

		// todo: the "disabled" aspect should probably be worked into the extractor being present in the first place
		//  since "IncludeRootGit" is always true
		gitrepo.Configure(tor, gitrepo.Config{
			IncludeRootGit: actions.IncludeGitRoot,
			Disabled:       !actions.IncludeGitRoot,
		})

		vendored.Configure(tor, vendored.Config{
			// Only attempt to vendor check git directories if we are not skipping scanning root git directories
			ScanGitDir: !actions.IncludeGitRoot,
			OSVClient:  accessors.OSVDevClient,
			Disabled:   accessors.OSVDevClient == nil,
		})
	}
}

func getPlugins(defaultPlugins []string, accessors ExternalAccessors, actions ScannerActions) []plugin.Plugin {
	if len(actions.ExtractorsEnabled) == 0 {
		actions.ExtractorsEnabled = defaultPlugins
	}

	var plugins []plugin.Plugin

	plugins = append(plugins, scalibrplugin.Resolve(actions.ExtractorsEnabled, actions.ExtractorsDisabled)...)
	plugins = append(plugins, scalibrplugin.Resolve(actions.DetectorsEnabled, actions.DetectorsDisabled)...)

	configurePlugins(plugins, accessors, actions)

	return plugins
}

func omitDirExtractors(extractors []plugin.Plugin) []plugin.Plugin {
	filtered := make([]plugin.Plugin, 0, len(extractors))

	for _, ext := range extractors {
		if ext.Requirements().ExtractFromDirs {
			continue
		}

		filtered = append(filtered, ext)
	}

	return filtered
}

// scan essentially converts ScannerActions into imodels.ScanResult by performing the extractions
func scan(accessors ExternalAccessors, actions ScannerActions) (*imodels.ScanResult, error) {
	//nolint:prealloc // We don't know how many inventories we will retrieve
	var scannedInventories []*extractor.Package
	var genericFindings []*inventory.GenericFinding

	plugins := getPlugins(
		[]string{"lockfile", "sbom", "directory"},
		accessors,
		actions,
	)

	if len(plugins) == 0 {
		return nil, errors.New("at least one extractor must be enabled")
	}

	// --- Lockfiles ---
	lockfileExtractors := omitDirExtractors(plugins)

	for _, lockfileElem := range actions.LockfilePaths {
		invs, err := scanners.ScanSingleFileWithMapping(lockfileElem, lockfileExtractors)
		if err != nil {
			return nil, err
		}

		scannedInventories = append(scannedInventories, invs...)
	}

	// --- SBOMs ---
	// none of the SBOM extractors need configuring
	sbomExtractors := scalibrplugin.BuildExtractors([]string{"sbom"})
	for _, sbomPath := range actions.SBOMPaths {
		path, err := filepath.Abs(sbomPath)
		if err != nil {
			cmdlogger.Errorf("Failed to resolved path %q with error: %s", path, err)
			return nil, err
		}

		invs, err := scanners.ScanSingleFile(path, sbomExtractors)
		if err != nil {
			cmdlogger.Infof("Failed to parse SBOM %q with error: %s", path, err)

			if errors.Is(err, scalibrextract.ErrExtractorNotFound) {
				cmdlogger.Infof("If you believe this is a valid SBOM, make sure the filename follows format per your SBOMs specification.")
			}

			return nil, err
		}

		scannedInventories = append(scannedInventories, invs...)
	}

	// --- Directories ---

	scanner := scalibr.New()

	// Build list of paths for each root
	// On linux this would return a map with just one entry of /
	rootMap := map[string][]string{}
	for _, path := range actions.DirectoryPaths {
		cmdlogger.Infof("Scanning dir %s", path)
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}

		_, err = os.Stat(absPath)
		if err != nil {
			return nil, fmt.Errorf("failed to scan dir: %w", err)
		}

		root := getRootDir(absPath)
		rootMap[root] = append(rootMap[root], absPath)
	}

	testlogger.BeginDirScanMarker()
	osCapability := determineOS()

	// For each root, run scalibr's scan() once.
	for root, paths := range rootMap {
		capabilities := plugin.Capabilities{
			DirectFS:      true,
			RunningSystem: true,
			Network:       plugin.NetworkOnline,
			OS:            osCapability,
		}

		if actions.CompareOffline {
			capabilities.Network = plugin.NetworkOffline
		}

		sr := scanner.Scan(context.Background(), &scalibr.ScanConfig{
			Plugins:               plugin.FilterByCapabilities(plugins, &capabilities),
			Capabilities:          &capabilities,
			ScanRoots:             fs.RealFSScanRoots(root),
			PathsToExtract:        paths,
			IgnoreSubDirs:         !actions.Recursive,
			DirsToSkip:            nil,
			SkipDirRegex:          nil,
			SkipDirGlob:           nil,
			UseGitignore:          !actions.NoIgnore,
			Stats:                 FileOpenedPrinter{},
			ReadSymlinks:          false,
			MaxInodes:             0,
			StoreAbsolutePath:     true,
			PrintDurationAnalysis: false,
			ErrorOnFSErrors:       false,
		})
		if sr.Status.Status != plugin.ScanStatusSucceeded {
			return nil, errors.New(sr.Status.FailureReason)
		}
		for _, status := range sr.PluginStatus {
			if status.Status.Status != plugin.ScanStatusSucceeded {
				cmdlogger.Errorf("Error during extraction: (extracting as %s) %s", status.Name, status.Status.FailureReason)
			}
		}
		genericFindings = append(genericFindings, sr.Inventory.GenericFindings...)
		scannedInventories = append(scannedInventories, sr.Inventory.Packages...)
	}

	testlogger.EndDirScanMarker()

	// Add on additional direct dependencies passed straight from ScannerActions:
	for _, commit := range actions.GitCommits {
		inv := &extractor.Package{
			SourceCode: &extractor.SourceCodeIdentifier{Commit: commit},
		}

		scannedInventories = append(scannedInventories, inv)
	}

	if len(scannedInventories) == 0 {
		return nil, ErrNoPackagesFound
	}

	scanResult := imodels.ScanResult{GenericFindings: genericFindings}

	// Convert to imodels.PackageScanResult for use in the rest of osv-scanner
	for _, inv := range scannedInventories {
		pi := imodels.FromInventory(inv)

		scanResult.PackageResults = append(
			scanResult.PackageResults,
			imodels.PackageScanResult{PackageInfo: pi},
		)
	}

	return &scanResult, nil
}

// getRootDir returns the root directory on each system.
// On Unix systems, it'll be /
// On Windows, it will most likely be the drive (e.g. C:\)
func getRootDir(path string) string {
	if runtime.GOOS == "windows" {
		return filepath.VolumeName(path) + "\\"
	}

	if strings.HasPrefix(path, "/") {
		return "/"
	}

	return ""
}

func determineOS() plugin.OS {
	switch runtime.GOOS {
	case "windows":
		return plugin.OSWindows
	case "darwin":
		return plugin.OSMac
	case "linux":
		return plugin.OSLinux
	default:
		cmdlogger.Warnf("Unknown OS \"%s\" - results might be inaccurate", runtime.GOOS)

		return plugin.OSAny
	}
}
