package osvscanner

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osvscanner/internal/scanners"
	"github.com/google/osv-scanner/pkg/reporter"
)

func scan(r reporter.Reporter, actions ScannerActions) ([]imodels.ScannedPackage, error) {
	//nolint:prealloc // Not sure how many there will be in advance.
	var scannedPackages []imodels.ScannedPackage

	// TODO(V2 Models): Temporarily initialize pom here to reduce PR size
	var pomExtractor filesystem.Extractor
	if !actions.TransitiveScanningActions.Disabled {
		var err error
		pomExtractor, err = createMavenExtractor(actions.TransitiveScanningActions)
		if err != nil {
			return nil, err
		}
	}

	if actions.ExperimentalScannerActions.ScanOCIImage != "" {
		r.Infof("Scanning image %s\n", actions.ExperimentalScannerActions.ScanOCIImage)
		pkgs, err := scanners.ScanImage(r, actions.ExperimentalScannerActions.ScanOCIImage)
		if err != nil {
			return nil, err
		}

		scannedPackages = append(scannedPackages, pkgs...)
	}

	if actions.DockerImageName != "" {
		pkgs, err := scanners.ScanDockerImage(r, actions.DockerImageName)
		if err != nil {
			return nil, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	for _, lockfileElem := range actions.LockfilePaths {
		parseAs, lockfilePath := parseLockfilePath(lockfileElem)
		lockfilePath, err := filepath.Abs(lockfilePath)
		if err != nil {
			r.Errorf("Failed to resolved path with error %s\n", err)
			return nil, err
		}
		pkgs, err := scanners.ScanLockfile(r, lockfilePath, parseAs, pomExtractor)
		if err != nil {
			return nil, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	for _, sbomElem := range actions.SBOMPaths {
		sbomElem, err := filepath.Abs(sbomElem)
		if err != nil {
			return nil, fmt.Errorf("failed to resolved path with error %w", err)
		}
		pkgs, err := scanners.ScanSBOMFile(r, sbomElem, false)
		if err != nil {
			return nil, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	for _, commit := range actions.GitCommits {
		scannedPackages = append(scannedPackages, imodels.ScannedPackage{
			Commit: commit,
			Source: models.SourceInfo{
				Path: "HASH",
				Type: "git",
			},
		})
	}

	for _, dir := range actions.DirectoryPaths {
		r.Infof("Scanning dir %s\n", dir)
		pkgs, err := scanners.ScanDir(r, dir, actions.SkipGit, actions.Recursive, !actions.NoIgnore, actions.CompareOffline, pomExtractor)
		if err != nil {
			return nil, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	if len(scannedPackages) == 0 {
		return nil, NoPackagesFoundErr
	}

	return scannedPackages, nil
}

func parseLockfilePath(lockfileElem string) (string, string) {
	if !strings.Contains(lockfileElem, ":") {
		lockfileElem = ":" + lockfileElem
	}

	splits := strings.SplitN(lockfileElem, ":", 2)

	return splits[0], splits[1]
}
