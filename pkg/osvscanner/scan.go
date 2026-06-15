package osvscanner

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/annotator"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/packagedeprecation"
	"github.com/google/osv-scalibr/enricher/reachability/java"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	scanconfig "github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/scalibrannotator/filter"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitcommitdirect"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
)

var ErrExtractorNotFound = errors.New("could not determine extractor suitable to this file")

func configurePlugins(plugins []plugin.Plugin, accessors ExternalAccessors, actions ScannerActions) {
	for _, plug := range plugins {
		vendored.Configure(plug, vendored.Config{
			// Only attempt to vendor check git directories if we are not skipping scanning root git directories
			ScanGitDir: !actions.IncludeGitRoot,
			OSVClient:  accessors.OSVDevClient,
		})
	}
}

func getPlugins(
	defaultPlugins []string,
	accessors ExternalAccessors,
	actions ScannerActions,
	clientFactories config.ClientFactories,
	configManager *scanconfig.Manager,
	isContainerScan bool,
) []plugin.Plugin {
	pluginSpecific := []*cpb.PluginSpecificConfig{
		{
			Config: &cpb.PluginSpecificConfig_PomXmlNet{
				PomXmlNet: &cpb.POMXMLNetConfig{
					UpstreamRegistry:    actions.TransitiveScanning.MavenRegistry,
					DepsDevRequirements: !actions.TransitiveScanning.NativeDataSource,
				},
			},
		},
		{
			Config: &cpb.PluginSpecificConfig_PythonRequirementsTransitive{
				PythonRequirementsTransitive: &cpb.PythonRequirementsTransitiveConfig{
					DepsDevRequirements: !actions.TransitiveScanning.NativeDataSource,
				},
			},
		},
	}

	pluginSpecific = append(pluginSpecific, &cpb.PluginSpecificConfig{
		Config: &cpb.PluginSpecificConfig_Osvlocal{
			Osvlocal: &cpb.OSVLocalConfig{
				Download:   actions.DownloadDatabases,
				LocalPath:  actions.LocalDBPath,
				RemoteHost: "https://osv-vulnerabilities.storage.googleapis.com",
			},
		},
	})
	pluginSpecific = append(pluginSpecific, &cpb.PluginSpecificConfig{
		Config: &cpb.PluginSpecificConfig_Osvdev{
			Osvdev: &cpb.OSVDevConfig{
				InitialQueryTimeoutSeconds: 300, // 5 minutes
			},
		},
	})

	cfg := &cpb.PluginConfig{
		UserAgent:      actions.RequestUserAgent,
		PluginSpecific: pluginSpecific,
	}

	if !actions.PluginsNoDefaults {
		actions.PluginsEnabled = append(actions.PluginsEnabled, defaultPlugins...)
	}

	if !actions.TransitiveScanning.Disabled {
		actions.PluginsEnabled = append(actions.PluginsEnabled, "transitive")
	}

	if !actions.IncludeGitRoot {
		actions.PluginsDisabled = append(actions.PluginsDisabled, gitrepo.Name)
	}

	if accessors.OSVDevClient == nil {
		actions.PluginsDisabled = append(actions.PluginsDisabled, vendored.Name)
	}

	if actions.CallAnalysisStates["jar"] {
		actions.PluginsEnabled = append(actions.PluginsEnabled, java.Name)
	}

	if actions.FlagDeprecatedPackages {
		actions.PluginsEnabled = append(actions.PluginsEnabled, packagedeprecation.Name)
	}

	if len(actions.ScanLicensesAllowlist) > 0 || actions.ScanLicensesSummary {
		actions.PluginsEnabled = append(actions.PluginsEnabled, "licenses")
	}

	if actions.CompareOffline {
		actions.PluginsEnabled = append(actions.PluginsEnabled, "vulnmatch/osvlocal")
	} else {
		actions.PluginsEnabled = append(actions.PluginsEnabled, "vulnmatch/osvdev")
	}

	plugins := scalibrplugin.Resolve(actions.PluginsEnabled, actions.PluginsDisabled, cfg, clientFactories)

	// Append the pre-matching filter annotator so it always runs.
	filterAnnotator := filter.NewAnnotator(configManager, isContainerScan, actions.ShowAllPackages)
	plugins = append(plugins, filterAnnotator)

	configurePlugins(plugins, accessors, actions)

	return plugins
}

func networkCapability(actions ScannerActions) plugin.Network {
	if actions.PluginNetworkDisabled && !actions.DownloadDatabases {
		return plugin.NetworkOffline
	}

	return plugin.NetworkOnline
}

// countNotEnrichers counts the number of plugins that are not enricher.Enricher plugins
func countNotEnrichersOrAnnotators(plugins []plugin.Plugin) int {
	count := 0
	for _, plug := range plugins {
		_, enricherOk := plug.(enricher.Enricher)
		_, annotatorOk := plug.(annotator.Annotator)
		if !enricherOk && !annotatorOk {
			count++
		}
	}

	return count
}

// scan essentially converts ScannerActions into imodels.ScanResult by performing the extractions
func scan(
	accessors ExternalAccessors,
	actions ScannerActions,
	clientFactories config.ClientFactories,
	configManager *scanconfig.Manager,
) (*inventory.Inventory, *filter.Annotator, error) {
	var inv inventory.Inventory

	plugins := getPlugins(
		[]string{"lockfile", "sbom", "directory"},
		accessors,
		actions,
		clientFactories,
		configManager,
		/* isContainerScan = */ false,
	)

	// technically having one detector enabled would also be sufficient, but we're
	// not mentioning them to avoid confusion since they're still in their infancy
	if countNotEnrichersOrAnnotators(plugins) == 0 {
		return nil, nil, errors.New("at least one extractor must be enabled")
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
		// path is user-controlled and is logged to stdout, which the GitHub Actions
		// runner parses for ::command::value sequences regardless of --format.
		// Sanitize \r/\n so an attacker-supplied directory name cannot inject
		// workflow commands.
		cmdlogger.Infof("Scanning dir %s", output.SanitizeForWorkflowCommand(path))
		if _, err := pathToRootMap(rootMap, path, actions.Recursive); err != nil {
			return nil, nil, err
		}
	}

	// --- Lockfiles ---
	for _, lockfileElem := range actions.LockfilePaths {
		parseAs, path := scanners.ParseLockfilePath(lockfileElem)
		absPath, err := pathToRootMap(rootMap, path, actions.Recursive)
		if err != nil {
			return nil, nil, err
		}

		specificPaths = append(specificPaths, absPath)

		if parseAs != "" {
			plug, err := scanners.ParseAsToPlugin(parseAs, plugins)
			if err != nil {
				return nil, nil, err
			}
			overrideMap[absPath] = plug
		}
	}

	// --- SBOMs (Deprecated) ---
	// none of the SBOM extractors need configuring
	sbomExtractors := scalibrplugin.Resolve([]string{"sbom"}, []string{}, &cpb.PluginConfig{}, config.NewDefaultClientFactories(""))

SBOMLoop:
	for _, sbomPath := range actions.SBOMPaths {
		absPath, err := pathToRootMap(rootMap, sbomPath, actions.Recursive)
		if err != nil {
			return nil, nil, err
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

		return nil, nil, fmt.Errorf("invalid SBOM filename: %s", sbomPath)
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
		return nil, nil, fmt.Errorf("failed to parse exclude patterns: %w", err)
	}

	capabilities := plugin.Capabilities{
		DirectFS:           true,
		RunningSystem:      true,
		Network:            networkCapability(actions),
		OS:                 osCapability,
		AllowUnsafePlugins: true,
	}

	filteredPlugins := append(plugin.FilterByCapabilities(plugins, &capabilities), gitDirectPlugin)

	// For each root, run scalibr's scan() once.
	for root, paths := range rootMap {
		sr := scanner.Scan(context.Background(), &scalibr.ScanConfig{
			Plugins:               filteredPlugins,
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
			return nil, nil, errors.New(sr.Status.FailureReason)
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
					fmt.Fprintf(&builder, "%s: %s", fileError.FilePath, fileError.ErrorMessage)

					// Check if the erroring file was a path specifically passed in (not a result of a file walk)
					if slices.Contains(specificPaths, filepath.Join(root, fileError.FilePath)) {
						criticalError = true
					}
				}

				msg := status.Status.FailureReason

				if len(status.Status.FileErrors) > 0 {
					msg = builder.String()
				}

				cmdlogger.Errorf("Error during extraction: (extracting as %s) %s", status.Name, msg)
				if criticalError {
					return nil, nil, errors.New("extraction failed on specified lockfile")
				}
			}
		}

		slices.SortFunc(sr.Inventory.Packages, inventorySort)
		pkgMap := make(map[*extractor.Package]*extractor.Package)
		var uniquePkgs []*extractor.Package
		if len(sr.Inventory.Packages) > 0 {
			kept := sr.Inventory.Packages[0]
			uniquePkgs = append(uniquePkgs, kept)
			for i := 1; i < len(sr.Inventory.Packages); i++ {
				current := sr.Inventory.Packages[i]
				if inventorySort(kept, current) == 0 {
					pkgMap[current] = kept
				} else {
					kept = current
					uniquePkgs = append(uniquePkgs, kept)
				}
			}
		}
		sr.Inventory.Packages = uniquePkgs

		for _, vuln := range sr.Inventory.PackageVulns {
			if kept, ok := pkgMap[vuln.Package]; ok {
				vuln.Package = kept
			}
		}
		sr.Inventory.PackageVulns = dedupPackageVulns(sr.Inventory.PackageVulns)

		inv.GenericFindings = append(inv.GenericFindings, sr.Inventory.GenericFindings...)
		inv.Packages = append(inv.Packages, sr.Inventory.Packages...)
		inv.PackageVulns = append(inv.PackageVulns, sr.Inventory.PackageVulns...)
	}

	testlogger.EndDirScanMarker()

	// Check if specific paths have been extracted.
	// This allows us to error if a specific file provided by the user failed to extract, and return an error for them.
	for _, path := range specificPaths {
		if _, ok := statsCollector.filesExtracted[path]; !ok {
			return nil, nil, fmt.Errorf("%w: %q", ErrExtractorNotFound, path)
		}
	}

	// Find the filter annotator instance in the plugins list so we can retrieve
	// any packages that were filtered out during the scan.
	var filterAnno *filter.Annotator
	for _, p := range plugins {
		if fa, ok := p.(*filter.Annotator); ok {
			filterAnno = fa
			break
		}
	}

	packagesExtracted := len(inv.Packages)
	if filterAnno != nil {
		packagesExtracted = filterAnno.PreFilteredPackageCount()
	}

	if packagesExtracted == 0 {
		return nil, nil, ErrNoPackagesFound
	}

	return &inv, filterAnno, nil
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

type vulnKey struct {
	pkg    *extractor.Package
	vulnID string
}

func dedupPackageVulns(vulns []*inventory.PackageVuln) []*inventory.PackageVuln {
	if len(vulns) == 0 {
		return vulns
	}

	dedupVulns := make(map[vulnKey]*inventory.PackageVuln)

	for _, vv := range vulns {
		k := vulnKey{vv.Package, vv.Vulnerability.Id}
		if v, ok := dedupVulns[k]; !ok {
			dedupVulns[k] = vv
		} else {
			// Merge plugins
			for _, p := range vv.Plugins {
				if !slices.Contains(v.Plugins, p) {
					v.Plugins = append(v.Plugins, p)
				}
			}
		}
	}

	result := make([]*inventory.PackageVuln, 0, len(dedupVulns))
	for _, v := range dedupVulns {
		result = append(result, v)
	}

	slices.SortFunc(result, func(a, b *inventory.PackageVuln) int {
		if a.Package == b.Package {
			return cmp.Compare(a.Vulnerability.Id, b.Vulnerability.Id)
		}
		return inventorySort(a.Package, b.Package)
	})

	return result
}
