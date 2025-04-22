package osvscanner

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packagesconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/cabal"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/stacklock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleverificationmetadataxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/ecosystemmock"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// scan essentially converts ScannerActions into PackageScanResult by performing the extractions
func scan(accessors ExternalAccessors, actions ScannerActions) ([]imodels.PackageScanResult, error) {
	//nolint:prealloc // We don't know how many inventories we will retrieve
	var scannedInventories []*extractor.Package

	// --- Lockfiles ---
	lockfileExtractors := scanners.BuildAll([]string{
		// C
		conanlock.Name,

		// Erlang
		mixlock.Name,

		// Flutter
		pubspec.Name,

		// Go
		gomod.Name,

		// Java
		gradlelockfile.Name,
		gradleverificationmetadataxml.Name,
		pomxmlenhanceable.Name,

		// Javascript
		packagelockjson.Name,
		pnpmlock.Name,
		yarnlock.Name,
		bunlock.Name,

		// PHP
		composerlock.Name,

		// Python
		pipfilelock.Name,
		pdmlock.Name,
		poetrylock.Name,
		requirements.Name,
		uvlock.Name,

		// R
		renvlock.Name,

		// Ruby
		gemfilelock.Name,

		// Rust
		cargolock.Name,

		// NuGet
		depsjson.Name,
		packagesconfig.Name,
		packageslockjson.Name,

		// Haskell
		cabal.Name,
		stacklock.Name,
		// TODO: map the extracted packages to SwiftURL in OSV.dev
		// The extracted package names do not match the package names of SwiftURL in OSV.dev,
		// so we need to find a workaround to map the names.
		// packageresolved.Extractor{},
	})

	if accessors.DependencyClients[osvschema.EcosystemMaven] != nil && accessors.MavenRegistryAPIClient != nil {
		for _, tor := range lockfileExtractors {
			pomxmlenhanceable.EnhanceIfPossible(tor, pomxmlnet.Config{
				DependencyClient:       accessors.DependencyClients[osvschema.EcosystemMaven],
				MavenRegistryAPIClient: accessors.MavenRegistryAPIClient,
			})
		}
	}
	for _, lockfileElem := range actions.LockfilePaths {
		invs, err := scanners.ScanSingleFileWithMapping(lockfileElem, lockfileExtractors)
		if err != nil {
			return nil, err
		}

		scannedInventories = append(scannedInventories, invs...)
	}

	// --- SBOMs ---
	sbomExtractors := scanners.BuildAll([]string{spdx.Name, cdx.Name})
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
	dirExtractors := make([]filesystem.Extractor, 0, len(lockfileExtractors)+len(sbomExtractors)+2)
	dirExtractors = append(dirExtractors, lockfileExtractors...)
	dirExtractors = append(dirExtractors, sbomExtractors...)

	// todo: see if we can move this into scanner.build
	if actions.IncludeGitRoot {
		dirExtractors = append(dirExtractors, gitrepo.Extractor{
			IncludeRootGit: actions.IncludeGitRoot,
		})
	}

	// todo: see if we can move this into scanner.build
	if accessors.OSVDevClient != nil {
		dirExtractors = append(dirExtractors, vendored.Extractor{
			// Only attempt to vendor check git directories if we are not skipping scanning root git directories
			ScanGitDir: !actions.IncludeGitRoot,
			OSVClient:  accessors.OSVDevClient,
		})
	}
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
