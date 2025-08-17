// Package scanners provides functionality for scanning lockfiles.
package scanners

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

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
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
)

var lockfileExtractorMapping = map[string][]string{
	"pubspec.lock":                {pubspec.Name},
	"pnpm-lock.yaml":              {pnpmlock.Name},
	"yarn.lock":                   {yarnlock.Name},
	"package-lock.json":           {packagelockjson.Name},
	"pom.xml":                     {pomxmlenhanceable.Name},
	"buildscript-gradle.lockfile": {gradlelockfile.Name},
	"gradle.lockfile":             {gradlelockfile.Name},
	"verification-metadata.xml":   {gradleverificationmetadataxml.Name},
	"poetry.lock":                 {poetrylock.Name},
	"Pipfile.lock":                {pipfilelock.Name},
	"pdm.lock":                    {pdmlock.Name},
	"requirements.txt":            {requirementsenhancable.Name},
	"uv.lock":                     {uvlock.Name},
	"Cargo.lock":                  {cargolock.Name},
	"composer.lock":               {composerlock.Name},
	"mix.lock":                    {mixlock.Name},
	"renv.lock":                   {renvlock.Name},
	"deps.json":                   {depsjson.Name},
	"packages.config":             {packagesconfig.Name},
	"packages.lock.json":          {packageslockjson.Name},
	"conan.lock":                  {conanlock.Name},
	"go.mod":                      {gomod.Name},
	"bun.lock":                    {bunlock.Name},
	"Gemfile.lock":                {gemfilelock.Name},
	"gems.locked":                 {gemfilelock.Name},
	"cabal.project.freeze":        {cabal.Name},
	"stack.yaml.lock":             {stacklock.Name},
	// "Package.resolved":            {packageresolved.Name},
}

// ScanSingleFile is similar to ScanSingleFileWithMapping, just without supporting the <lockfileformat>:/path/to/lockfile prefix identifier
func ScanSingleFile(path string, extractorsToUse []plugin.Plugin) ([]*extractor.Package, error) {
	invs, err := scalibrextract.ExtractWithExtractors(context.Background(), path, extractorsToUse)
	if err != nil {
		return nil, err
	}

	pkgCount := len(invs)
	if pkgCount > 0 {
		cmdlogger.Infof(
			"Scanned %s file and found %d %s",
			path,
			pkgCount,
			output.Form(pkgCount, "package", "packages"),
		)
	}

	return invs, nil
}

// ScanSingleFileWithMapping will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
func ScanSingleFileWithMapping(scanPath string, pluginsToUse []plugin.Plugin) ([]*extractor.Package, error) {
	var err error
	var inventories []*extractor.Package

	parseAs, path := parseLockfilePath(scanPath)

	path, err = filepath.Abs(path)
	if err != nil {
		cmdlogger.Errorf("Failed to resolved path %q with error: %s", path, err)
		return nil, err
	}

	// special case for the APK and DPKG parsers because they have a very generic name while
	// living at a specific location, so they are not included in the map of parsers
	// used by lockfile.Parse to avoid false-positives when scanning projects
	switch parseAs {
	case "apk-installed":
		inventories, err = scalibrextract.ExtractWithExtractor(context.Background(), path, apk.New(apk.DefaultConfig()))
	case "dpkg-status":
		inventories, err = scalibrextract.ExtractWithExtractor(context.Background(), path, dpkg.New(dpkg.DefaultConfig()))
	case "osv-scanner":
		inventories, err = scalibrextract.ExtractWithExtractor(context.Background(), path, osvscannerjson.Extractor{})
	case "": // No specific parseAs specified
		inventories, err = scalibrextract.ExtractWithExtractors(context.Background(), path, pluginsToUse)
	default: // A specific parseAs without a special case is selected
		// Find and extract with the extractor of parseAs
		if names, ok := lockfileExtractorMapping[parseAs]; ok && len(names) > 0 {
			i := slices.IndexFunc(pluginsToUse, func(plug plugin.Plugin) bool {
				_, ok = plug.(filesystem.Extractor)

				return ok && slices.Contains(names, plug.Name())
			})
			if i < 0 {
				return nil, fmt.Errorf("could not determine extractor, requested %s", parseAs)
			}
			inventories, err = scalibrextract.ExtractWithExtractor(context.Background(), path, pluginsToUse[i].(filesystem.Extractor))
		} else {
			return nil, fmt.Errorf("could not determine extractor, requested %s", parseAs)
		}
	}

	if err != nil {
		return nil, err
	}

	parsedAsComment := ""

	if parseAs != "" {
		parsedAsComment = fmt.Sprintf("as a %s ", parseAs)
	}

	pkgCount := len(inventories)

	cmdlogger.Infof(
		"Scanned %s file %sand found %d %s",
		path,
		parsedAsComment,
		pkgCount,
		output.Form(pkgCount, "package", "packages"),
	)

	return inventories, nil
}

func parseLockfilePath(scanArg string) (string, string) {
	if (runtime.GOOS == "windows" && filepath.IsAbs(scanArg)) || !strings.Contains(scanArg, ":") {
		scanArg = ":" + scanArg
	}

	splits := strings.SplitN(scanArg, ":", 2)

	return splits[0], splits[1]
}
