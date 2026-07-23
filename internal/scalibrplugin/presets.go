package scalibrplugin

import (
	annotatorlist "github.com/google/osv-scalibr/annotator/list"
	"github.com/google/osv-scalibr/annotator/misc/brewsource"
	apkanno "github.com/google/osv-scalibr/annotator/osduplicate/apk"
	dpkganno "github.com/google/osv-scalibr/annotator/osduplicate/dpkg"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	detectors "github.com/google/osv-scalibr/detector/list"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/enricher/enricherlist"
	transitivedependencypomxml "github.com/google/osv-scalibr/enricher/transitivedependency/pomxml"
	transitivedependencyrequirements "github.com/google/osv-scalibr/enricher/transitivedependency/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/csproj"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/nugetcpm"
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
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/swift/packageresolved"
	extractors "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/chisel"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
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
		spdx.Name: {protoCfg(spdx.New)},
		cdx.Name:  {protoCfg(cdx.New)},
	},
	"lockfile": {
		// C
		conanlock.Name: {protoCfg(conanlock.New)},

		// Erlang
		mixlock.Name: {protoCfg(mixlock.New)},

		// Flutter
		pubspec.Name: {protoCfg(pubspec.New)},

		// Go
		gomod.Name: {protoCfg(gomod.New)},

		// Java
		gradlelockfile.Name:                {protoCfg(gradlelockfile.New)},
		gradleverificationmetadataxml.Name: {protoCfg(gradleverificationmetadataxml.New)},
		pomxml.Name:                        {protoCfg(pomxml.New)},

		// Javascript
		packagelockjson.Name: {protoCfg(packagelockjson.New)},
		pnpmlock.Name:        {protoCfg(pnpmlock.New)},
		yarnlock.Name:        {protoCfg(yarnlock.New)},
		bunlock.Name:         {protoCfg(bunlock.New)},

		// PHP
		composerlock.Name: {protoCfg(composerlock.New)},

		// Python
		pipfilelock.Name:  {protoCfg(pipfilelock.New)},
		pdmlock.Name:      {protoCfg(pdmlock.New)},
		poetrylock.Name:   {protoCfg(poetrylock.New)},
		pylock.Name:       {protoCfg(pylock.New)},
		requirements.Name: {protoCfg(requirements.New)},
		uvlock.Name:       {protoCfg(uvlock.New)},

		// R
		renvlock.Name: {protoCfg(renvlock.New)},

		// Ruby
		gemfilelock.Name: {protoCfg(gemfilelock.New)},

		// Swift
		packageresolved.Name: {protoCfg(packageresolved.New)},

		// Rust
		cargolock.Name: {protoCfg(cargolock.New)},

		// NuGet
		csproj.Name:           {protoCfg(csproj.New)},
		depsjson.Name:         {protoCfg(depsjson.New)},
		nugetcpm.Name:         {protoCfg(nugetcpm.New)},
		packagesconfig.Name:   {protoCfg(packagesconfig.New)},
		packageslockjson.Name: {protoCfg(packageslockjson.New)},

		// Haskell
		cabal.Name:     {protoCfg(cabal.New)},
		stacklock.Name: {protoCfg(stacklock.New)},

		osvscannerjson.Name: {protoCfg(osvscannerjson.New)},

		// --- OS "lockfiles" ---
		// These have very strict FileRequired paths, so we can safely enable them for source scanning as well.
		// Alpine
		apk.Name: {protoCfg(apk.New)},
		// Debian
		dpkg.Name: {protoCfg(dpkg.New)},
	},
	"directory": {
		gitrepo.Name:  {protoCfg(gitrepo.New)},
		vendored.Name: {protoCfg(vendored.New)},
	},
	"artifact": {
		// --- Project artifacts ---
		// Python
		wheelegg.Name: {protoCfg(wheelegg.New)},
		// Java
		archive.Name: {protoCfg(archive.New)},
		// Go
		gobinary.Name: {protoCfg(gobinary.New)},
		// Javascript
		nodemodules.Name: {protoCfg(nodemodules.New)},
		// Rust
		cargoauditable.Name: {protoCfg(cargoauditable.New)},

		// --- OS packages ---
		// Alpine
		apk.Name: {protoCfg(apk.New)},
		// Debian
		dpkg.Name: {protoCfg(dpkg.New)},
		// Chisel
		chisel.Name: {protoCfg(chisel.New)},
		// Homebrew
		homebrew.Name: {protoCfg(homebrew.New)},
	},
}

var enricherPresets = map[string]enricherlist.InitMap{
	"artifact": {
		baseimage.Name: {baseimage.New},
	},
	"vulns":    enricherlist.VulnMatching,
	"licenses": enricherlist.License,
	"transitive": {
		transitivedependencyrequirements.Name: {transitivedependencyrequirements.New},
		transitivedependencypomxml.Name:       {transitivedependencypomxml.New},
	},
}

var annotatorPresets = map[string]annotatorlist.InitMap{
	"artifact": {
		apkanno.Name:    {protoCfg(apkanno.New)},
		dpkganno.Name:   {protoCfg(dpkganno.New)},
		brewsource.Name: {protoCfg(brewsource.New)},
	},
}

func protoCfg[T plugin.Plugin](f func(*cpb.PluginConfig) (T, error)) func(*config.PluginConfig) (T, error) {
	return func(cfg *config.PluginConfig) (T, error) {
		if cfg != nil && cfg.ProtoConfig != nil {
			return f(cfg.ProtoConfig)
		}

		return f(&cpb.PluginConfig{})
	}
}
