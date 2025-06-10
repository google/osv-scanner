package osvscanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/builders"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func configureExtractors(extractors []filesystem.Extractor, accessors ExternalAccessors, actions ScannerActions) {
	for _, tor := range extractors {
		if accessors.DependencyClients[osvschema.EcosystemMaven] != nil && accessors.MavenRegistryAPIClient != nil {
			pomxmlenhanceable.EnhanceIfPossible(tor, pomxmlnet.Config{
				DependencyClient:       accessors.DependencyClients[osvschema.EcosystemMaven],
				MavenRegistryAPIClient: accessors.MavenRegistryAPIClient,
			})
		}

		//if accessors.DependencyClients[osvschema.EcosystemPyPI] != nil && accessors.MavenRegistryAPIClient != nil {
		//	requirementsenhancable.EnhanceIfPossible(tor, requirementsnet.Config{
		//			Extractor: tor,
		//			Client: ,
		//		},
		//	))
		//}

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

func getExtractors(defaultExtractorNames []string, accessors ExternalAccessors, actions ScannerActions) []filesystem.Extractor {
	extractors := actions.Extractors

	if len(extractors) == 0 {
		extractors = builders.BuildExtractors(defaultExtractorNames)
	}

	configureExtractors(extractors, accessors, actions)

	return extractors
}

// scan essentially converts ScannerActions into PackageScanResult by performing the extractions
func scan(accessors ExternalAccessors, actions ScannerActions) ([]imodels.PackageScanResult, error) {
	//nolint:prealloc // We don't know how many inventories we will retrieve
	var scannedInventories []*extractor.Package

	// --- Lockfiles ---
	lockfileExtractors := getExtractors(scalibrextract.ExtractorsLockfiles, accessors, actions)
	for _, lockfileElem := range actions.LockfilePaths {
		invs, err := scanners.ScanSingleFileWithMapping(lockfileElem, lockfileExtractors)
		if err != nil {
			return nil, err
		}

		scannedInventories = append(scannedInventories, invs...)
	}

	// --- SBOMs ---
	// none of the SBOM extractors need configuring
	sbomExtractors := builders.BuildExtractors(scalibrextract.ExtractorsSBOMs)
	for _, sbomPath := range actions.SBOMPaths {
		path, err := filepath.Abs(sbomPath)
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to resolved path %q with error: %s", path, err))
			return nil, err
		}

		invs, err := scanners.ScanSingleFile(path, sbomExtractors)
		if err != nil {
			slog.Info(fmt.Sprintf("Failed to parse SBOM %q with error: %s", path, err))

			if errors.Is(err, scalibrextract.ErrExtractorNotFound) {
				slog.Info("If you believe this is a valid SBOM, make sure the filename follows format per your SBOMs specification.")
			}

			return nil, err
		}

		scannedInventories = append(scannedInventories, invs...)
	}

	// --- Directories ---
	dirExtractors := getExtractors(
		slices.Concat(
			scalibrextract.ExtractorsLockfiles,
			scalibrextract.ExtractorsSBOMs,
			scalibrextract.ExtractorsDirectories,
		),
		accessors,
		actions,
	)

	scanner := scalibr.New()

	// Build list of paths for each root
	// On linux this would return a map with just one entry of /
	rootMap := map[string][]string{}
	for _, path := range actions.DirectoryPaths {
		slog.Info(fmt.Sprintf("Scanning dir %s", path))

		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		root := getRootDir(absPath)
		rootMap[root] = append(rootMap[root], absPath)
	}

	for root, paths := range rootMap {
		capabilities := plugin.Capabilities{
			DirectFS:      true,
			RunningSystem: true,
		}

		if actions.CompareOffline {
			capabilities.Network = plugin.NetworkOffline
		} else {
			capabilities.Network = plugin.NetworkOnline
		}

		if runtime.GOOS == "windows" {
			capabilities.OS = plugin.OSWindows
		} else {
			capabilities.OS = plugin.OSUnix
		}

		sr := scanner.Scan(context.Background(), &scalibr.ScanConfig{
			FilesystemExtractors:  dirExtractors,
			StandaloneExtractors:  nil,
			Detectors:             nil,
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

		for _, pkg := range sr.Inventory.Packages {
			for i := range pkg.Locations {
				pkg.Locations[i] = filepath.Join(root, pkg.Locations[i])
			}
			scannedInventories = append(scannedInventories, pkg)
		}
	}

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

	// Convert to imodels.PackageScanResult for use in the rest of osv-scanner
	packages := []imodels.PackageScanResult{}
	for _, inv := range scannedInventories {
		pi := imodels.FromInventory(inv)

		packages = append(packages, imodels.PackageScanResult{
			PackageInfo: pi,
		})
	}

	return packages, nil
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
