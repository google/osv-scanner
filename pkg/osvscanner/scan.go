package osvscanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/ecosystemmock"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
)

// scan essentially converts ScannerActions into PackageScanResult by performing the extractions
func scan(accessors ExternalAccessors, actions ScannerActions) ([]imodels.PackageScanResult, error) {
	//nolint:prealloc // We don't know how many inventories we will retrieve
	var scannedInventories []*extractor.Package

	// --- Lockfiles ---
	lockfileExtractors := scanners.BuildLockfileExtractors(accessors.DependencyClients, accessors.MavenRegistryAPIClient)
	for _, lockfileElem := range actions.LockfilePaths {
		invs, err := scanners.ScanSingleFileWithMapping(lockfileElem, lockfileExtractors)
		if err != nil {
			return nil, err
		}

		scannedInventories = append(scannedInventories, invs...)
	}

	// --- SBOMs ---
	sbomExtractors := scanners.BuildSBOMExtractors()
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
	dirExtractors := scanners.BuildWalkerExtractors(
		actions.IncludeGitRoot,
		accessors.OSVDevClient,
		accessors.DependencyClients,
		accessors.MavenRegistryAPIClient,
	)

	scanner := scalibr.New()
	//pathsToExtract := make([]string, 0, len(actions.DirectoryPaths))

	for _, path := range actions.DirectoryPaths {
		slog.Info(fmt.Sprintf("Scanning dir %s", path))
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		root := getRootDir(absPath)

		var networkCap plugin.Network
		if actions.CompareOffline {
			networkCap = plugin.NetworkOffline
		} else {
			networkCap = plugin.NetworkOnline
		}

		sr := scanner.Scan(context.Background(), &scalibr.ScanConfig{
			FilesystemExtractors: dirExtractors,
			StandaloneExtractors: nil,
			Detectors:            nil,
			Capabilities: &plugin.Capabilities{
				// TODO: Pass though plugin status
				OS:            plugin.OSLinux,
				Network:       networkCap,
				DirectFS:      true,
				RunningSystem: true,
			},
			ScanRoots:             fs.RealFSScanRoots(root),
			PathsToExtract:        []string{absPath},
			IgnoreSubDirs:         !actions.Recursive,
			DirsToSkip:            nil,
			SkipDirRegex:          nil,
			SkipDirGlob:           nil,
			UseGitignore:          !actions.NoIgnore,
			Stats:                 nil,
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
			Extractor:  ecosystemmock.Extractor{}, // Empty ecosystem
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
