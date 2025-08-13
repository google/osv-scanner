package scalibrplugin

import (
	detectors "github.com/google/osv-scalibr/detector/list"
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
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	extractors "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

var detectorPresets = map[string]detectors.InitMap{
	"cis":         detectors.CIS,
	"govulncheck": detectors.Govulncheck,
	"untested":    detectors.Untested,
	"weakcreds":   detectors.Weakcredentials,
}

var ExtractorPresets = map[string]extractors.InitMap{
	"sbom": {
		spdx.Name: {spdx.New},
		cdx.Name:  {cdx.New},
	},
	"lockfile": {
		// C
		conanlock.Name: {conanlock.New},

		// Erlang
		mixlock.Name: {mixlock.New},

		// Flutter
		pubspec.Name: {pubspec.New},

		// Go
		gomod.Name: {gomod.New},

		// Java
		gradlelockfile.Name:                {gradlelockfile.New},
		gradleverificationmetadataxml.Name: {gradleverificationmetadataxml.New},
		pomxmlenhanceable.Name:             {pomxmlenhanceable.New},

		// Javascript
		packagelockjson.Name: {packagelockjson.NewDefault},
		pnpmlock.Name:        {pnpmlock.New},
		yarnlock.Name:        {yarnlock.New},
		bunlock.Name:         {bunlock.New},

		// PHP
		composerlock.Name: {composerlock.New},

		// Python
		pipfilelock.Name:            {pipfilelock.New},
		pdmlock.Name:                {pdmlock.New},
		poetrylock.Name:             {poetrylock.New},
		requirementsenhancable.Name: {requirementsenhancable.New},
		uvlock.Name:                 {uvlock.New},

		// R
		renvlock.Name: {renvlock.New},

		// Ruby
		gemfilelock.Name: {gemfilelock.New},

		// Rust
		cargolock.Name: {cargolock.New},

		// NuGet
		depsjson.Name:         {depsjson.NewDefault},
		packagesconfig.Name:   {packagesconfig.NewDefault},
		packageslockjson.Name: {packageslockjson.NewDefault},

		// Haskell
		cabal.Name:     {cabal.NewDefault},
		stacklock.Name: {stacklock.NewDefault},
	},
	"directory": {
		gitrepo.Name:  {gitrepo.New},
		vendored.Name: {vendored.New},
	},
	"artifact": {
		// --- Project artifacts ---
		// Python
		wheelegg.Name: {wheelegg.NewDefault},
		// Java
		archive.Name: {archive.NewDefault},
		// Go
		gobinary.Name: {gobinary.NewDefault},
		// Javascript
		nodemodules.Name: {nodemodules.New},
		// Rust
		cargoauditable.Name: {cargoauditable.NewDefault},

		// --- OS packages ---
		// Alpine
		apk.Name: {apk.NewDefault},
		// Debian
		dpkg.Name: {dpkg.NewDefault},
	},
}
