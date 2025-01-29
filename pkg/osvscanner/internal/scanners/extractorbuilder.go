package scanners

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
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
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scanner/v2/internal/datasource"
	"github.com/google/osv-scanner/v2/internal/osvdev"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlnet"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var sbomExtractors = []filesystem.Extractor{
	spdx.Extractor{},
	cdx.Extractor{},
}

var lockfileExtractors = []filesystem.Extractor{
	conanlock.Extractor{},
	packageslockjson.Extractor{},
	mixlock.Extractor{},
	pubspec.Extractor{},
	gomod.Extractor{},
	gradlelockfile.Extractor{},
	gradleverificationmetadataxml.Extractor{},
	packagelockjson.Extractor{},
	pnpmlock.Extractor{},
	yarnlock.Extractor{},
	composerlock.Extractor{},
	pipfilelock.Extractor{},
	pdmlock.Extractor{},
	poetrylock.Extractor{},
	requirements.Extractor{},
	renvlock.Extractor{},
	gemfilelock.Extractor{},
	cargolock.Extractor{},
	uvlock.Extractor{},
	depsjson.Extractor{},
	cabal.Extractor{},
	stacklock.Extractor{},
	// TODO: map the extracted packages to SwiftURL in OSV.dev
	// The extracted package names do not match the package names of SwiftURL in OSV.dev,
	// so we need to find a workaround to map the names.
	// packageresolved.Extractor{},
}

// BuildLockfileExtractors returns all relevant extractors for lockfile scanning given the required clients
// All clients can be nil, and if nil the extractors requiring those clients will not be returned.
func BuildLockfileExtractors(dependencyClients map[osvschema.Ecosystem]client.DependencyClient, mavenAPIClient *datasource.MavenRegistryAPIClient) []filesystem.Extractor {
	extractorsToUse := lockfileExtractors

	if dependencyClients[osvschema.EcosystemMaven] != nil && mavenAPIClient != nil {
		extractorsToUse = append(extractorsToUse, pomxmlnet.Extractor{
			DependencyClient:       dependencyClients[osvschema.EcosystemMaven],
			MavenRegistryAPIClient: mavenAPIClient,
		})
	} else {
		extractorsToUse = append(extractorsToUse, pomxml.Extractor{})
	}

	return extractorsToUse
}

// BuildSBOMExtractors returns extractors relevant to SBOM extraction
func BuildSBOMExtractors() []filesystem.Extractor {
	return sbomExtractors
}

// BuildWalkerExtractors returns all relevant extractors for directory scanning given the required clients
// All clients can be nil, and if nil the extractors requiring those clients will not be returned.
func BuildWalkerExtractors(
	skipGit bool,
	osvdevClient *osvdev.OSVClient,
	dependencyClients map[osvschema.Ecosystem]client.DependencyClient,
	mavenAPIClient *datasource.MavenRegistryAPIClient) []filesystem.Extractor {
	relevantExtractors := []filesystem.Extractor{}

	if !skipGit {
		relevantExtractors = append(relevantExtractors, gitrepo.Extractor{})
	}
	relevantExtractors = append(relevantExtractors, lockfileExtractors...)
	relevantExtractors = append(relevantExtractors, sbomExtractors...)

	if osvdevClient != nil {
		relevantExtractors = append(relevantExtractors, vendored.Extractor{
			ScanGitDir: skipGit,
			OSVClient:  osvdevClient,
		})
	}

	if dependencyClients[osvschema.EcosystemMaven] != nil && mavenAPIClient != nil {
		relevantExtractors = append(relevantExtractors, pomxmlnet.Extractor{
			DependencyClient:       dependencyClients[osvschema.EcosystemMaven],
			MavenRegistryAPIClient: mavenAPIClient,
		})
	} else {
		relevantExtractors = append(relevantExtractors, pomxml.Extractor{})
	}

	return relevantExtractors
}

// BuildArtifactExtractors returns all relevant extractors for artifact scanning given the required clients
// All clients can be nil, and if nil the extractors requiring those clients will not be returned.
func BuildArtifactExtractors() []filesystem.Extractor {
	extractorsToUse := []filesystem.Extractor{
		// --- Project artifacts ---
		// Python
		wheelegg.New(wheelegg.DefaultConfig()),
		// Java
		archive.New(archive.DefaultConfig()),
		// Go
		gobinary.New(gobinary.DefaultConfig()),
		// Javascript
		nodemodules.Extractor{},

		// --- OS packages ---
		// Alpine
		apk.New(apk.DefaultConfig()),
		// Debian
		// TODO: Add tests for debian containers
		dpkg.New(dpkg.DefaultConfig()),
	}

	return extractorsToUse
}
