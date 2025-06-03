package osvscanner

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scanner/v2/internal/builders"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/ecosystemmock"
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

	for _, dir := range actions.DirectoryPaths {
		slog.Info("Scanning dir " + dir)
		pkgs, err := scanners.ScanDir(dir, actions.Recursive, !actions.NoIgnore, dirExtractors)
		if err != nil {
			return nil, err
		}
		scannedInventories = append(scannedInventories, pkgs...)
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
