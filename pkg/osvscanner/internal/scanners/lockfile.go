package scanners

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
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
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/scalibrextract"
	"github.com/google/osv-scanner/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/pkg/reporter"
)

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
}

var lockfileExtractorMapping = map[string]string{
	"pubspec.lock":      "dart/pubspec",
	"pnpm-lock.yaml":    "javascript/pnpmlock",
	"yarn.lock":         "javascript/yarnlock",
	"package-lock.json": "javascript/packagelockjson",
	// This translation works for both the transitive scanning and non transitive scanning
	// As both extractors have the same name
	"pom.xml":                     "java/pomxml",
	"buildscript-gradle.lockfile": "java/gradlelockfile",
	"gradle.lockfile":             "java/gradlelockfile",
	"verification-metadata.xml":   "java/gradleverificationmetadataxml",
	"poetry.lock":                 "python/poetrylock",
	"Pipfile.lock":                "python/Pipfilelock",
	"pdm.lock":                    "python/pdmlock",
	"requirements.txt":            "python/requirements",
	"Cargo.lock":                  "rust/Cargolock",
	"composer.lock":               "php/composerlock",
	"mix.lock":                    "erlang/mixlock",
	"renv.lock":                   "r/renvlock",
	"packages.lock.json":          "dotnet/packageslockjson",
	"conan.lock":                  "cpp/conanlock",
	"go.mod":                      "go/gomod",
	"Gemfile.lock":                "ruby/gemfilelock",
}

// ScanLockfile will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
//
// TODO(V2 Models): pomExtractor is temporary until V2 Models
func ScanLockfile(r reporter.Reporter, scanArg string, pomExtractor filesystem.Extractor) ([]*extractor.Inventory, error) {
	var err error
	var inventories []*extractor.Inventory

	parseAs, path := parseLockfilePath(scanArg)

	path, err = filepath.Abs(path)
	if err != nil {
		r.Errorf("Failed to resolved path %q with error: %s\n", path, err)
		return nil, err
	}
	extractorsToUse := lockfileExtractors

	if pomExtractor != nil {
		extractorsToUse = append(extractorsToUse, pomExtractor)
	} else {
		extractorsToUse = append(extractorsToUse, pomxml.Extractor{})
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
		inventories, err = scalibrextract.ExtractWithExtractors(context.Background(), path, extractorsToUse)
	default: // A specific parseAs without a special case is selected
		// Find and extract with the extractor of parseAs
		if name, ok := lockfileExtractorMapping[parseAs]; ok {
			for _, ext := range extractorsToUse {
				if name == ext.Name() {
					inventories, err = scalibrextract.ExtractWithExtractor(context.Background(), path, ext)
					break
				}
			}
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

	r.Infof(
		"Scanned %s file %sand found %d %s\n",
		path,
		parsedAsComment,
		pkgCount,
		output.Form(pkgCount, "package", "packages"),
	)

	return inventories, nil
}

func parseLockfilePath(scanArg string) (string, string) {
	if !strings.Contains(scanArg, ":") {
		scanArg = ":" + scanArg
	}

	splits := strings.SplitN(scanArg, ":", 2)

	return splits[0], splits[1]
}
