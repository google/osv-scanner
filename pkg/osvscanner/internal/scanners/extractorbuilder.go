package scanners

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packagesconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/cabal"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/stacklock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleverificationmetadataxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
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
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/osvdev"
)

func build(name string) filesystem.Extractor {
	switch name {
	// Alpine
	case apk.Name:
		return apk.NewDefault()

	// C
	case conanlock.Name:
		return conanlock.New()

	// Debian
	case dpkg.Name:
		return dpkg.NewDefault()

	// Erlang
	case mixlock.Name:
		return mixlock.New()

	// Flutter
	case pubspec.Name:
		return pubspec.New()

	// Go
	case gomod.Name:
		return gomod.New()
	case gobinary.Name:
		return gobinary.NewDefault()

	// Haskell
	case cabal.Name:
		return cabal.NewDefault()
	case stacklock.Name:
		return stacklock.NewDefault()

	// Java
	case gradlelockfile.Name:
		return gradlelockfile.New()
	case gradleverificationmetadataxml.Name:
		return gradleverificationmetadataxml.New()
	case archive.Name:
		return archive.NewDefault()

	// Javascript
	case packagelockjson.Name:
		return packagelockjson.NewDefault()
	case pnpmlock.Name:
		return pnpmlock.New()
	case yarnlock.Name:
		return yarnlock.New()
	case bunlock.Name:
		return bunlock.New()
	case nodemodules.Name:
		return nodemodules.Extractor{}

	// NuGet
	case depsjson.Name:
		return depsjson.NewDefault()
	case packagesconfig.Name:
		return packagesconfig.NewDefault()
	case packageslockjson.Name:
		return packageslockjson.NewDefault()

	// PHP
	case composerlock.Name:
		return composerlock.New()

	// Python
	case pipfilelock.Name:
		return pipfilelock.New()
	case pdmlock.Name:
		return pdmlock.New()
	case poetrylock.Name:
		return poetrylock.New()
	case requirements.Name:
		return requirements.NewDefault()
	case uvlock.Name:
		return uvlock.New()
	case wheelegg.Name:
		return wheelegg.NewDefault()

	// R
	case renvlock.Name:
		return renvlock.New()

	// Ruby
	case gemfilelock.Name:
		return gemfilelock.New()

	// Rust
	case cargolock.Name:
		return cargolock.New()
	case cargoauditable.Name:
		return cargoauditable.NewDefault()

	// SBOM
	case spdx.Name:
		return spdx.New()
	case cdx.Name:
		return cdx.New()
	}

	return nil
}

func buildAll(names []string) []filesystem.Extractor {
	extractors := make([]filesystem.Extractor, 0, len(names))

	for _, name := range names {
		extractors = append(extractors, build(name))
	}

	return extractors
}

// Build returns all relevant extractors for the given preset
func Build(
	preset string,
	includeGitRoot bool,
	osvdevClient *osvdev.OSVClient,
	dependencyClients map[osvschema.Ecosystem]resolve.Client,
	mavenAPIClient *datasource.MavenRegistryAPIClient,
) []filesystem.Extractor {
	switch preset {
	case "lockfile":
		return buildLockfileExtractors(dependencyClients, mavenAPIClient)
	case "sbom":
		return buildAll([]string{spdx.Name, cdx.Name})
	case "walker":
		return buildWalkerExtractors(includeGitRoot, osvdevClient, dependencyClients, mavenAPIClient)
	case "artifact":
		return buildAll([]string{
			// --- Project artifacts ---
			// Python
			wheelegg.Name,
			// Java
			archive.Name,
			// Go
			gobinary.Name,
			// Javascript
			"javascript/nodemodules",
			// Rust
			cargoauditable.Name,

			// --- OS packages ---
			// Alpine
			apk.Name,
			// Debian
			// TODO: Add tests for debian containers
			dpkg.Name,
		})
	}

	return nil
}

// buildLockfileExtractors returns all relevant extractors for lockfile scanning given the required clients
// All clients can be nil, and if nil the extractors requiring those clients will not be returned.
func buildLockfileExtractors(dependencyClients map[osvschema.Ecosystem]resolve.Client, mavenAPIClient *datasource.MavenRegistryAPIClient) []filesystem.Extractor {
	extractorsToUse := BuildAll([]string{
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

	if dependencyClients[osvschema.EcosystemMaven] != nil && mavenAPIClient != nil {
		extractorsToUse = append(extractorsToUse, pomxmlnet.New(pomxmlnet.Config{
			DependencyClient:       dependencyClients[osvschema.EcosystemMaven],
			MavenRegistryAPIClient: mavenAPIClient,
		}))
	} else {
		extractorsToUse = append(extractorsToUse, pomxml.Extractor{})
	}

	return extractorsToUse
}

// buildWalkerExtractors returns all relevant extractors for directory scanning given the required clients
// All clients can be nil, and if nil the extractors requiring those clients will not be returned.
func buildWalkerExtractors(
	includeRootGit bool,
	osvdevClient *osvdev.OSVClient,
	dependencyClients map[osvschema.Ecosystem]resolve.Client,
	mavenAPIClient *datasource.MavenRegistryAPIClient) []filesystem.Extractor {
	relevantExtractors := []filesystem.Extractor{}

	if includeRootGit {
		relevantExtractors = append(relevantExtractors, gitrepo.Extractor{
			IncludeRootGit: includeRootGit,
		})
	}
	for _, preset := range []string{"lockfile", "sbom"} {
		relevantExtractors = append(relevantExtractors,
			Build(
				preset,
				includeRootGit,
				osvdevClient,
				dependencyClients,
				mavenAPIClient,
			)...,
		)
	}

	if osvdevClient != nil {
		relevantExtractors = append(relevantExtractors, vendored.Extractor{
			// Only attempt to vendor check git directories if we are not skipping scanning root git directories
			ScanGitDir: !includeRootGit,
			OSVClient:  osvdevClient,
		})
	}

	return relevantExtractors
}
