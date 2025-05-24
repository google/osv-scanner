package scalibrextract

import (
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

var ExtractorsSBOMs = []string{
	spdx.Name,
	cdx.Name,
}

var ExtractorsLockfiles = []string{
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
}

var ExtractorsDirectories = []string{
	gitrepo.Name,
	vendored.Name,
}

var ExtractorsArtifacts = []string{
	// --- Project artifacts ---
	// Python
	wheelegg.Name,
	// Java
	archive.Name,
	// Go
	gobinary.Name,
	// Javascript
	nodemodules.Name,
	// Rust
	cargoauditable.Name,

	// --- OS packages ---
	// Alpine
	apk.Name,
	// Debian
	dpkg.Name,
}
