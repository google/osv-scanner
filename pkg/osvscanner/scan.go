package osvscanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/enricher/reachability/java"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirementsnet"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
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

func configurePlugins(plugins []plugin.Plugin, accessors ExternalAccessors, actions ScannerActions) {
	for _, plug := range plugins {
		if accessors.DependencyClients[osvschema.EcosystemMaven] != nil && accessors.MavenRegistryAPIClient != nil {
			pomxmlenhanceable.EnhanceIfPossible(plug, pomxmlnet.Config{
				DependencyClient:       accessors.DependencyClients[osvschema.EcosystemMaven],
				MavenRegistryAPIClient: accessors.MavenRegistryAPIClient,
			})
		}
		if accessors.DependencyClients[osvschema.EcosystemPyPI] != nil {
			requirementsenhancable.EnhanceIfPossible(plug, requirementsnet.Config{
				Extractor: &requirements.Extractor{},
				Client:    accessors.DependencyClients[osvschema.EcosystemPyPI],
			})
		}

		vendored.Configure(plug, vendored.Config{
			// Only attempt to vendor check git directories if we are not skipping scanning root git directories
			ScanGitDir: !actions.IncludeGitRoot,
			OSVClient:  accessors.OSVDevClient,
		})
	}
}

func getPlugins(defaultPlugins []string, accessors ExternalAccessors, actions ScannerActions) []plugin.Plugin {
	if !actions.PluginsNoDefaults {
		actions.PluginsEnabled = append(actions.PluginsEnabled, defaultPlugins...)
	}

	if !actions.IncludeGitRoot {
		actions.PluginsDisabled = append(actions.PluginsDisabled, gitrepo.Name)
	}

	if accessors.OSVDevClient == nil {
		actions.PluginsDisabled = append(actions.PluginsDisabled, vendored.Name)
	}

	plugins := scalibrplugin.Resolve(actions.PluginsEnabled, actions.PluginsDisabled)

	configurePlugins(plugins, accessors, actions)

	return plugins
}

// omitDirExtractors removes any plugins that require extracting from a directory
func omitDirExtractors(plugins []plugin.Plugin) []plugin.Plugin {
	filtered := make([]plugin.Plugin, 0, len(plugins))

	for _, plug := range plugins {
		if plug.Requirements().ExtractFromDirs {
			continue
		}

		filtered = append(filtered, plug)
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

	if actions.CallAnalysisStates["jar"] {
		plugins = append(plugins, java.NewDefault())
	}

	// --- Lockfiles ---
	//lockfilePlugins := omitDirExtractors(plugins)

	scanner := scalibr.New()

	// Build list of paths for each root
	// On linux this would return a map with just one entry of /
	rootMap := map[string][]string{}

	// Also build a map of specific plugin overrides that the user specify
	// map[path]parseAs
	overrideMap := map[string]filesystem.Extractor{}
	var specificPaths []string
	statsCollector := fileOpenedPrinter{
		filesExtracted: make(map[string]struct{}),
	}

	// --- Directories ---
	for _, path := range actions.DirectoryPaths {
		cmdlogger.Infof("Scanning dir %s", path)
		if _, err := pathToRootMap(rootMap, path, actions.Recursive); err != nil {
			return nil, err
		}
	}

	// --- Lockfiles ---
	for _, lockfileElem := range actions.LockfilePaths {
		parseAs, path := scanners.ParseLockfilePath(lockfileElem)

		//cmdlogger.Infof("Scanning lockfiles %s", path)
		if absPath, err := pathToRootMap(rootMap, path, actions.Recursive); err != nil {
			return nil, err
		} else {
			specificPaths = append(specificPaths, absPath)

			if parseAs != "" {
				plug, err := scanners.ParseAsToPlugin(parseAs, plugins)
				if err != nil {
					return nil, err
				}
				overrideMap[absPath] = plug
			}
		}
	}

	// --- SBOMs (Deprecated) ---
	// none of the SBOM extractors need configuring
	sbomExtractors := scalibrplugin.Resolve([]string{"sbom"}, []string{})

SBOMLoop:
	for _, sbomPath := range actions.SBOMPaths {
		if absPath, err := pathToRootMap(rootMap, sbomPath, actions.Recursive); err != nil {
			return nil, err
		} else {
			specificPaths = append(specificPaths, absPath)

			for _, se := range sbomExtractors {
				// All sbom extractors are filesystem extractors
				sbomExtractor := se.(filesystem.Extractor)
				if sbomExtractor.FileRequired(simplefileapi.New(absPath, nil)) {
					overrideMap[absPath] = sbomExtractor
					continue SBOMLoop
				}
			}
			cmdlogger.Errorf("Failed to parse SBOM %q: Invalid SBOM filename.", sbomPath)
			cmdlogger.Errorf("If you believe this is a valid SBOM, make sure the filename follows format per your SBOMs specification.")

			return nil, fmt.Errorf("invalid SBOM filename: %s", sbomPath)
		}
	}

	testlogger.BeginDirScanMarker()
	osCapability := determineOS()

	//var statsCollector stats.Collector
	//if actions.StatsCollector != nil {
	//	statsCollector = actions.StatsCollector
	//} else {
	//	statsCollector = fileOpenedPrinter{}
	//}

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
			Stats:                 statsCollector,
			ReadSymlinks:          false,
			MaxInodes:             0,
			StoreAbsolutePath:     true,
			PrintDurationAnalysis: false,
			ErrorOnFSErrors:       false,
			ExtractorOverride: func(api filesystem.FileAPI) []filesystem.Extractor {
				ext, ok := overrideMap[filepath.Join(root, api.Path())]
				if ok {
					return []filesystem.Extractor{ext}
				} else {
					return []filesystem.Extractor{}
				}
			},
		})

		if sr.Status.Status == plugin.ScanStatusFailed {
			return nil, errors.New(sr.Status.FailureReason)
		}
		for _, status := range sr.PluginStatus {
			if status.Status.Status != plugin.ScanStatusSucceeded {
				builder := strings.Builder{}
				criticalError := false
				for _, fileError := range status.Status.FileErrors {
					if len(status.Status.FileErrors) > 1 {
						// If there is more than 1 file error, write them on new lines
						builder.WriteString("\n\t")
					}
					builder.WriteString(fmt.Sprintf("%s: %s", fileError.FilePath, fileError.ErrorMessage))

					// Check if the erroring file was a path specifically passed in (not a result of a file walk)
					for _, path := range specificPaths {
						if strings.Contains(filepath.ToSlash(path), filepath.ToSlash(fileError.FilePath)) {
							criticalError = true
							break
						}
					}
				}
				cmdlogger.Errorf("Error during extraction: (extracting as %s) %s", status.Name, builder.String())
				if criticalError {
					return nil, errors.New("extraction failed on specified lockfile")
				}
			}
		}

		// Check if specific paths have been extracted
		for _, path := range specificPaths {
			key, _ := filepath.Rel(root, path)
			if _, ok := statsCollector.filesExtracted[key]; !ok {
				return nil, fmt.Errorf("%w: %q", scalibrextract.ErrExtractorNotFound, path)
			}
		}

		slices.SortFunc(sr.Inventory.Packages, inventorySort)
		invsCompact := slices.CompactFunc(sr.Inventory.Packages, func(a, b *extractor.Package) bool {
			return inventorySort(a, b) == 0
		})
		sr.Inventory.Packages = invsCompact

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

// pathToRootMap saves the absolute path into the root map, and returns the absolute path.
// path is only saved if it does not fall under an existing path.
// IMPORTANT: it does not remove existing paths already added to the rootMap, so add directories before specific files.
func pathToRootMap(rootMap map[string][]string, path string, recursive bool) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	fi, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	root := getRootDir(absPath)
	// If path is a directory and we are not recursively scanning, then always add it as a target.
	if fi.IsDir() && !recursive {
		rootMap[root] = append(rootMap[root], absPath)
		return absPath, nil
	}

	// Otherwise, only add if it's not a descendent of an existing path
	for _, existing := range rootMap[root] {
		if isDescendent(existing, absPath, recursive) {
			return absPath, nil
		}
	}
	rootMap[root] = append(rootMap[root], absPath)

	return absPath, nil
}

func isDescendent(potentialParent, path string, recursive bool) bool {
	rel, err := filepath.Rel(potentialParent, path)
	if err != nil {
		// This should never happen
		return false
	}

	if rel == "." {
		// Same as an existing path, skip
		return true
	}

	if strings.HasPrefix(rel, "..") {
		return false
	}

	depths := len(strings.Split(rel, string(filepath.Separator)))
	if recursive {
		// Descendant of existing dir, and we are recursively scanning, so skip
		return true
	}

	if depths == 1 {
		// Direct child of existing dir, skip
		return true
	}

	return false
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
