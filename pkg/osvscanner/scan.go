package osvscanner

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/pomxmlnet"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/pkg/osvscanner/internal/scanners"
	"github.com/google/osv-scanner/pkg/reporter"
)

// scan performs all the required scanning actions and returns the results as a slice of inventories.
func scan(r reporter.Reporter, actions ScannerActions) ([]*extractor.Inventory, error) {
	//nolint:prealloc // Not sure how many there will be in advance.
	var scannedInventory []*extractor.Inventory

	// TODO(V2 Models): Temporarily initialize pom here to reduce PR size
	var pomExtractor filesystem.Extractor
	if !actions.TransitiveScanningActions.Disabled {
		var err error
		pomExtractor, err = createMavenExtractor(actions.TransitiveScanningActions)
		if err != nil {
			return nil, err
		}
	}

	for _, lockfileElem := range actions.LockfilePaths {
		parseAs, lockfilePath := parseLockfilePath(lockfileElem)

		invs, err := scanners.ScanLockfile(r, lockfilePath, parseAs, pomExtractor)
		if err != nil {
			return nil, err
		}

		scannedInventory = append(scannedInventory, invs...)
	}

	for _, sbomPath := range actions.SBOMPaths {
		invs, err := scanners.ScanSBOM(r, sbomPath)
		if err != nil {
			return nil, err
		}

		scannedInventory = append(scannedInventory, invs...)
	}

	for _, dir := range actions.DirectoryPaths {
		r.Infof("Scanning dir %s\n", dir)
		pkgs, err := scanners.ScanDir(r, dir, actions.SkipGit, actions.Recursive, !actions.NoIgnore, actions.CompareOffline, pomExtractor)
		if err != nil {
			return nil, err
		}
		scannedInventory = append(scannedInventory, pkgs...)
	}

	if len(scannedInventory) == 0 {
		return nil, NoPackagesFoundErr
	}

	return scannedInventory, nil
}

func parseLockfilePath(lockfileElem string) (string, string) {
	if !strings.Contains(lockfileElem, ":") {
		lockfileElem = ":" + lockfileElem
	}

	splits := strings.SplitN(lockfileElem, ":", 2)

	return splits[0], splits[1]
}

func createMavenExtractor(actions TransitiveScanningActions) (*pomxmlnet.Extractor, error) {
	var depClient client.DependencyClient
	var err error
	if actions.NativeDataSource {
		depClient, err = client.NewMavenRegistryClient(actions.MavenRegistry)
	} else {
		depClient, err = client.NewDepsDevClient(depsdev.DepsdevAPI)
	}
	if err != nil {
		return nil, err
	}

	mavenClient, err := datasource.NewMavenRegistryAPIClient(actions.MavenRegistry)
	if err != nil {
		return nil, err
	}

	extractor := pomxmlnet.Extractor{
		DependencyClient:       depClient,
		MavenRegistryAPIClient: mavenClient,
	}

	return &extractor, nil
}
