package osvscanner

import (
	"fmt"
	"log/slog"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/ecosystemmock"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
)

// scan essentially converts ScannerActions into PackageScanResult by performing the extractions
func scan(accessors ExternalAccessors, actions ScannerActions) ([]imodels.PackageScanResult, error) {
	//nolint:prealloc // We don't know how many inventories we will retrieve
	var scannedInventories []*extractor.Inventory

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
		invs, err := scanners.ScanSingleFile(sbomPath, sbomExtractors)
		if err != nil {
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
	for _, dir := range actions.DirectoryPaths {
		slog.Info(fmt.Sprintf("Scanning dir %s\n", dir))
		pkgs, err := scanners.ScanDir(dir, actions.Recursive, !actions.NoIgnore, dirExtractors)
		if err != nil {
			return nil, err
		}
		scannedInventories = append(scannedInventories, pkgs...)
	}

	// Add on additional direct dependencies passed straight from ScannerActions:
	for _, commit := range actions.GitCommits {
		inv := &extractor.Inventory{
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
