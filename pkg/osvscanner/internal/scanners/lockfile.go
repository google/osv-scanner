// Package scanners provides functionality for scanning lockfiles.
package scanners

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

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
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
)

// OSV-Scanner and OSV-Scalibr has different plugin/override naming conventions.
var osvscannerScalibrExtractionMapping = map[string][]string{
	"apk-installed":               {apk.Name},
	"dpkg-status":                 {dpkg.Name},
	"pubspec.lock":                {pubspec.Name},
	"pnpm-lock.yaml":              {pnpmlock.Name},
	"yarn.lock":                   {yarnlock.Name},
	"package-lock.json":           {packagelockjson.Name},
	"pom.xml":                     {pomxml.Name},
	"buildscript-gradle.lockfile": {gradlelockfile.Name},
	"gradle.lockfile":             {gradlelockfile.Name},
	"verification-metadata.xml":   {gradleverificationmetadataxml.Name},
	"poetry.lock":                 {poetrylock.Name},
	"Pipfile.lock":                {pipfilelock.Name},
	"pdm.lock":                    {pdmlock.Name},
	"pylock.toml":                 {pylock.Name},
	"requirements.txt":            {requirements.Name},
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

// ParseLockfilePath returns (parseAs, path)
func ParseLockfilePath(scanArg string) (string, string) {
	if runtime.GOOS == "windows" && filepath.IsAbs(scanArg) {
		return "", scanArg
	}

	parseAs, path, found := strings.Cut(scanArg, ":")
	if !found {
		path = parseAs
		parseAs = ""
	}

	return parseAs, path
}

// ParseAsToPlugin finds the parseAs extractor in the list of pluginsToUse
func ParseAsToPlugin(parseAs string, pluginsToUse []plugin.Plugin) (filesystem.Extractor, error) {
	switch parseAs {
	case "": // No specific parseAs specified
		return nil, errors.New("no parseAs specified")
	case "osv-scanner":
		return osvscannerjson.Extractor{}, nil
	default:
		// Find and extract with the extractor of parseAs
		if names, ok := osvscannerScalibrExtractionMapping[parseAs]; ok && len(names) > 0 {
			i := slices.IndexFunc(pluginsToUse, func(plug plugin.Plugin) bool {
				_, ok = plug.(filesystem.Extractor)

				return ok && slices.Contains(names, plug.Name())
			})
			if i < 0 {
				return nil, fmt.Errorf("could not determine extractor, requested %s", parseAs)
			}

			fsysExtractor, ok := pluginsToUse[i].(filesystem.Extractor)
			if !ok {
				return nil, fmt.Errorf("invalid extractor name %s", parseAs)
			}

			return fsysExtractor, nil
		}

		return nil, fmt.Errorf("could not determine extractor, requested %s", parseAs)
	}
}
