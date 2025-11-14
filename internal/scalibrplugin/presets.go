package scalibrplugin

import (
	annotatorlist "github.com/google/osv-scalibr/annotator/list"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	detectors "github.com/google/osv-scalibr/detector/list"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/enricher/enricherlist"
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
	"github.com/google/osv-scanner/v2/internal/datasource"
	"github.com/google/osv-scanner/v2/internal/depsdev"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/imagepackagefilter"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/internal/version"
)

var detectorPresets = map[string]detectors.InitMap{
	"cis":         detectors.CIS,
	"govulncheck": detectors.Govulncheck,
	"untested":    detectors.Untested,
	"weakcreds":   detectors.Weakcredentials,
}

var ExtractorPresets = map[string]extractors.InitMap{
	"sbom": {
		spdx.Name: {noCFG(spdx.New)},
		cdx.Name:  {noCFG(cdx.New)},
	},
	"lockfile": {
		// C
		conanlock.Name: {noCFG(conanlock.New)},

		// Erlang
		mixlock.Name: {noCFG(mixlock.New)},

		// Flutter
		pubspec.Name: {noCFG(pubspec.New)},

		// Go
		gomod.Name: {noCFG(gomod.New)},

		// Java
		gradlelockfile.Name:                {noCFG(gradlelockfile.New)},
		gradleverificationmetadataxml.Name: {noCFG(gradleverificationmetadataxml.New)},
		pomxmlenhanceable.Name:             {noCFG(pomxmlenhanceable.New)},

		// Javascript
		packagelockjson.Name: {noCFG(packagelockjson.NewDefault)},
		pnpmlock.Name:        {noCFG(pnpmlock.New)},
		yarnlock.Name:        {noCFG(yarnlock.New)},
		bunlock.Name:         {noCFG(bunlock.New)},

		// PHP
		composerlock.Name: {noCFG(composerlock.New)},

		// Python
		pipfilelock.Name:            {noCFG(pipfilelock.New)},
		pdmlock.Name:                {noCFG(pdmlock.New)},
		poetrylock.Name:             {noCFG(poetrylock.New)},
		requirementsenhancable.Name: {noCFG(requirementsenhancable.New)},
		uvlock.Name:                 {noCFG(uvlock.New)},

		// R
		renvlock.Name: {noCFG(renvlock.New)},

		// Ruby
		gemfilelock.Name: {noCFG(gemfilelock.New)},

		// Rust
		cargolock.Name: {noCFG(cargolock.New)},

		// NuGet
		depsjson.Name:         {noCFG(depsjson.NewDefault)},
		packagesconfig.Name:   {noCFG(packagesconfig.NewDefault)},
		packageslockjson.Name: {noCFG(packageslockjson.NewDefault)},

		// Haskell
		cabal.Name:     {noCFG(cabal.NewDefault)},
		stacklock.Name: {noCFG(stacklock.NewDefault)},

		osvscannerjson.Name: {noCFG(osvscannerjson.New)},

		// --- OS "lockfiles" ---
		// These have very strict FileRequired paths, so we can safely enable them for source scanning as well.
		// Alpine
		apk.Name: {noCFG(apk.NewDefault)},
		// Debian
		dpkg.Name: {noCFG(dpkg.NewDefault)},
	},
	"directory": {
		gitrepo.Name:  {noCFG(gitrepo.New)},
		vendored.Name: {noCFG(vendored.New)},
	},
	"artifact": {
		// --- Project artifacts ---
		// Python
		wheelegg.Name: {noCFG(wheelegg.NewDefault)},
		// Java
		archive.Name: {noCFG(archive.NewDefault)},
		// Go
		gobinary.Name: {gobinary.New},
		// Javascript
		nodemodules.Name: {noCFG(nodemodules.New)},
		// Rust
		cargoauditable.Name: {noCFG(cargoauditable.NewDefault)},

		// --- OS packages ---
		// Alpine
		apk.Name: {noCFG(apk.NewDefault)},
		// Debian
		dpkg.Name: {noCFG(dpkg.NewDefault)},
	},
}

var enricherPresets = map[string]enricherlist.InitMap{
	"artifact": {
		baseimage.Name: {noCFGEnricher(baseImageEnricher)},
	},
	"vulns":    enricherlist.VulnMatching,
	"licenses": enricherlist.License,
}

var annotatorPresets = map[string]annotatorlist.InitMap{
	"artifact": {
		imagepackagefilter.Name: {imagepackagefilter.New},
	},
}

func baseImageEnricher() enricher.Enricher {
	// The grpc client **does not** make any requests. It starts in an IDLE state until
	// the first function call is made. This means we can safely initialize the client even in offline mode,
	// and the enricher plugin will be filtered out in offline mode.
	insightsClient, err := datasource.NewInsightsAlphaClient(depsdev.DepsdevAPI, "osv-scanner_scan/"+version.OSVVersion)
	if err != nil {
		panic("unable to connect to insights server")
	}

	baseImageEnricher, err := baseimage.New(&baseimage.Config{
		Client: baseimage.NewClientGRPC(insightsClient),
	})

	// These panics should be very unlikely to happen. Does **not** happen when network is not available.
	if err != nil {
		panic("unable to initialize base image enricher")
	}

	return baseImageEnricher
}

// Wraps initer functions that don't take any config value to initer functions that do.
// TODO(b/400910349): Remove once all plugins take config values.
// Copied from osv-scalibr
func noCFG(f func() filesystem.Extractor) extractors.InitFn {
	return func(_ *cpb.PluginConfig) filesystem.Extractor { return f() }
}

// Wraps initer functions that don't take any config value to initer functions that do.
// TODO(b/400910349): Remove once all plugins take config values.
// Copied from osv-scalibr
func noCFGEnricher(f func() enricher.Enricher) enricherlist.InitFn {
	return func(_ *cpb.PluginConfig) enricher.Enricher { return f() }
}
