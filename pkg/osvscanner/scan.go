package osvscanner

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/datasource"
	"github.com/google/osv-scanner/internal/scalibrextract/ecosystemmock"
	"github.com/google/osv-scanner/internal/scalibrextract/language/java/pomxmlnet"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/osvscanner/internal/scanners"
	"github.com/google/osv-scanner/pkg/reporter"
)

// scan essentially converts ScannerActions into PackageScanResult by performing the extractions
func scan(r reporter.Reporter, actions ScannerActions) ([]imodels.PackageScanResult, error) {
	var scannedInventories []*extractor.Inventory

	// TODO(V2 Models): Temporarily initialize pom here to reduce PR size
	// Eventually, we want to move TransitiveScanningActions into its own models package to avoid
	// cyclic imports
	var pomExtractor filesystem.Extractor
	if !actions.TransitiveScanningActions.Disabled {
		var err error
		pomExtractor, err = createMavenExtractor(actions.TransitiveScanningActions)
		if err != nil {
			return nil, err
		}
	}

	// --- Lockfiles ---
	for _, lockfileElem := range actions.LockfilePaths {
		invs, err := scanners.ScanLockfile(r, lockfileElem, pomExtractor)
		if err != nil {
			return nil, err
		}

		scannedInventories = append(scannedInventories, invs...)
	}

	// --- SBOMs ---
	for _, sbomPath := range actions.SBOMPaths {
		invs, err := scanners.ScanSBOM(r, sbomPath)
		if err != nil {
			return nil, err
		}

		scannedInventories = append(scannedInventories, invs...)
	}

	// --- Directories ---
	for _, dir := range actions.DirectoryPaths {
		r.Infof("Scanning dir %s\n", dir)
		pkgs, err := scanners.ScanDir(r, dir, actions.SkipGit, actions.Recursive, !actions.NoIgnore, pomExtractor)
		if err != nil {
			return nil, err
		}
		scannedInventories = append(scannedInventories, pkgs...)
	}

	if len(scannedInventories) == 0 {
		return nil, NoPackagesFoundErr
	}

	// Convert to imodels.PackageScanResult for use in the rest of osv-scanner
	packages := []imodels.PackageScanResult{}
	for _, inv := range scannedInventories {
		pi := imodels.FromInventory(inv)

		packages = append(packages, imodels.PackageScanResult{
			PackageInfo: pi,
		})
	}

	// Add on additional direct dependencies passed straight from ScannerActions:
	for _, commit := range actions.GitCommits {
		pi := imodels.PackageInfo{
			Inventory: &extractor.Inventory{
				SourceCode: &extractor.SourceCodeIdentifier{Commit: commit},
				Extractor:  ecosystemmock.Extractor{}, // Empty ecosystem
			},
		}

		packages = append(packages, imodels.PackageScanResult{
			PackageInfo: pi,
		})
	}

	return packages, nil
}

func createMavenExtractor(actions TransitiveScanningActions) (*pomxmlnet.Extractor, error) {
	var depClient client.DependencyClient
	var err error
	if actions.NativeDataSource {
		depClient, err = client.NewMavenRegistryClient(actions.MavenRegistry)
	} else {
		depClient, err = client.NewDepsDevClient(depsdev.DepsdevAPI, "osv-scanner_scan/"+version.OSVVersion)
	}
	if err != nil {
		return nil, err
	}

	mavenClient, err := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: actions.MavenRegistry, ReleasesEnabled: true})
	if err != nil {
		return nil, err
	}

	extractor := pomxmlnet.Extractor{
		DependencyClient:       depClient,
		MavenRegistryAPIClient: mavenClient,
	}

	return &extractor, nil
}
