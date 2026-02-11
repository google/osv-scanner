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
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/packagedeprecation"
	"github.com/google/osv-scalibr/enricher/reachability/java"
	transitivedependencyrequirements "github.com/google/osv-scalibr/enricher/transitivedependency/requirements"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitcommitdirect"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
)

var ErrExtractorNotFound = errors.New("could not determine extractor suitable to this file")

func configurePlugins(plugins []plugin.Plugin, accessors ExternalAccessors, actions ScannerActions) {
	for _, plug := range plugins {
		if !actions.TransitiveScanning.Disabled {
			err := pomxmlenhanceable.EnhanceIfPossible(plug, &cpb.PluginConfig{
				UserAgent: actions.RequestUserAgent,
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{
						Config: &cpb.PluginSpecificConfig_PomXmlNet{
							PomXmlNet: &cpb.POMXMLNetConfig{
								UpstreamRegistry:    actions.TransitiveScanning.MavenRegistry,
								DepsDevRequirements: !actions.TransitiveScanning.NativeDataSource,
							},
						},
					},
				},
			})
			if err != nil {
				log.Errorf("Failed to enhance pomxml extractor: %v", err)
			}
		}

		vendored.Configure(plug, vendored.Config{
			// Only attempt to vendor check git directories if we are not skipping scanning root git directories
			ScanGitDir: !actions.IncludeGitRoot,
			OSVClient:  accessors.OSVDevClient,
		})
	}
}

func isRequirementsExtractorEnabled(plugins []plugin.Plugin) bool {
	for _, plug := range plugins {
		_, ok := plug.(*requirements.Extractor)

		if ok {
			return true
		}
	}

	return false
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

	// TODO: Use Enricher.RequiredPlugins to check this generically
	if !actions.TransitiveScanning.Disabled && isRequirementsExtractorEnabled(plugins) {
		p, err := transitivedependencyrequirements.New(&cpb.PluginConfig{
			UserAgent: actions.RequestUserAgent,
		})
		if err != nil {
			log.Errorf("Failed to make transitivedependencyrequirements enricher: %v", err)
		} else {
			plugins = append(plugins, p)
		}
	}

	configurePlugins(plugins, accessors, actions)

	return plugins
}

// countNotEnrichers counts the number of plugins that are not enricher.Enricher plugins
func countNotEnrichers(plugins []plugin.Plugin) int {
	count := 0
	for _, plug := range plugins {
		_, ok := plug.(enricher.Enricher)
		if !ok {
			count++
		}
	}

	return count
}

// scan essentially converts ScannerActions into imodels.ScanResult by performing the extractions
func scan(accessors ExternalAccessors, actions ScannerActions) (*inventory.Inventory, error) {
	var inv inventory.Inventory

	plugins := getPlugins(
		[]string{"lockfile", "sbom", "directory"},
		accessors,
		actions,
	)

	// technically having one detector enabled would also be sufficient, but we're
	// not mentioning them to avoid confusion since they're still in their infancy
	if countNotEnrichers(plugins) == 0 {
		return nil, errors.New("at least one extractor must be enabled")
	}

	if actions.CallAnalysisStates["jar"] {
		plugins = append(plugins, java.NewDefault())
	}

	if actions.FlagDeprecatedPackages {
		p, err := packagedeprecation.New(&cpb.PluginConfig{
			UserAgent: actions.RequestUserAgent,
		})
		if err != nil {
			log.Errorf("Failed to make packagedeprecation enricher: %v", err)
		} else {
			plugins = append(plugins, p)
		}
	}

	scanner := scalibr.New()

	// Build list of paths for each root
	// On linux this would return a map with just one entry of /
	rootMap := map[string][]string{}

	// Also build a map of specific plugin overrides that the user specify
	// map[path]parseAs
	overrideMap := map[string]filesystem.Extractor{}
	// List of specific paths the user passes in so that we can check that they all get processed.
	specificPaths := make([]string, 0, len(actions.LockfilePaths)+len(actions.SBOMPaths))

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
		absPath, err := pathToRootMap(rootMap, path, actions.Recursive)
		if err != nil {
			return nil, err
		}

		specificPaths = append(specificPaths, absPath)

		if parseAs != "" {
			plug, err := scanners.ParseAsToPlugin(parseAs, plugins)
			if err != nil {
				return nil, err
			}
			overrideMap[absPath] = plug
		}
	}

	// --- SBOMs (Deprecated) ---
	// none of the SBOM extractors need configuring
	sbomExtractors := scalibrplugin.Resolve([]string{"sbom"}, []string{})

SBOMLoop:
	for _, sbomPath := range actions.SBOMPaths {
		absPath, err := pathToRootMap(rootMap, sbomPath, actions.Recursive)
		if err != nil {
			return nil, err
		}
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

	// --- Add git commits directly ---
	gitDirectPlugin := gitcommitdirect.New(actions.GitCommits)

	if len(rootMap) == 0 && len(actions.GitCommits) > 0 {
		// Even if there's no actual paths, if we have git commits, still do the scan
		rootMap = map[string][]string{
			"/": {},
		}
	}

	testlogger.BeginDirScanMarker()
	osCapability := determineOS()

	// Parse exclude patterns (supports exact names, glob, and regex)
	excludePatterns, err := parseExcludePatterns(actions.ExcludePatterns)
	if err != nil {
		return nil, fmt.Errorf("failed to parse exclude patterns: %w", err)
	}

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
			Plugins:               append(plugin.FilterByCapabilities(plugins, &capabilities), gitDirectPlugin),
			Capabilities:          &capabilities,
			ScanRoots:             fs.RealFSScanRoots(root),
			PathsToExtract:        paths,
			IgnoreSubDirs:         !actions.Recursive,
			DirsToSkip:            excludePatterns.dirsToSkip,
			SkipDirRegex:          excludePatterns.regexPattern,
			SkipDirGlob:           excludePatterns.globPattern,
			UseGitignore:          !actions.NoIgnore,
			Stats:                 &statsCollector,
			ReadSymlinks:          false,
			MaxInodes:             0,
			StoreAbsolutePath:     true,
			PrintDurationAnalysis: false,
			ErrorOnFSErrors:       false,
			ExplicitPlugins:       true,
			ExtractorOverride: func(api filesystem.FileAPI) []filesystem.Extractor {
				ext, ok := overrideMap[filepath.Join(root, filepath.FromSlash(api.Path()))]
				if ok {
					return []filesystem.Extractor{ext}
				}

				return []filesystem.Extractor{}
			},
		})

		// --- Check status of the run ---
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
					if slices.Contains(specificPaths, filepath.Join(root, fileError.FilePath)) {
						criticalError = true
					}
				}
				cmdlogger.Errorf("Error during extraction: (extracting as %s) %s", status.Name, builder.String())
				if criticalError {
					return nil, errors.New("extraction failed on specified lockfile")
				}
			}
		}

		slices.SortFunc(sr.Inventory.Packages, inventorySort)
		invsCompact := slices.CompactFunc(sr.Inventory.Packages, func(a, b *extractor.Package) bool {
			return inventorySort(a, b) == 0
		})
		sr.Inventory.Packages = invsCompact

		inv.GenericFindings = append(inv.GenericFindings, sr.Inventory.GenericFindings...)
		inv.Packages = append(inv.Packages, sr.Inventory.Packages...)
	}

	testlogger.EndDirScanMarker()

	// Check if specific paths have been extracted.
	// This allows us to error if a specific file provided by the user failed to extract, and return an error for them.
	for _, path := range specificPaths {
		if _, ok := statsCollector.filesExtracted[path]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrExtractorNotFound, path)
		}
	}

	if len(inv.Packages) == 0 {
		return nil, ErrNoPackagesFound
	}

	return &inv, nil
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

// isDescendent returns whether `path` is either a descendent or a direct child of `potentialParent`
// recursive = true: checks for descendents
// recursive = false: checks for direct children
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
