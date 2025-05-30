package builders

import (
	"log/slog"

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
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
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
	case pomxmlenhanceable.Name:
		return pomxmlenhanceable.New()
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

	// Directories
	case vendored.Name:
		return &vendored.Extractor{}
	case gitrepo.Name:
		return &gitrepo.Extractor{}
	}

	return nil
}

func BuildExtractors(names []string) []filesystem.Extractor {
	extractors := make([]filesystem.Extractor, 0, len(names))

	for _, name := range names {
		extractor := build(name)

		if extractor == nil {
			slog.Error("Unknown extractor " + name)
		} else {
			extractors = append(extractors, build(name))
		}
	}

	return extractors
}
