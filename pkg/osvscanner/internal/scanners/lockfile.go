package scanners

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
)

var lockfileExtractorMapping = map[string][]string{
	"pubspec.lock":                {"dart/pubspec"},
	"pnpm-lock.yaml":              {"javascript/pnpmlock"},
	"yarn.lock":                   {"javascript/yarnlock"},
	"package-lock.json":           {"javascript/packagelockjson"},
	"pom.xml":                     {"java/pomxmlnet", "java/pomxml"},
	"buildscript-gradle.lockfile": {"java/gradlelockfile"},
	"gradle.lockfile":             {"java/gradlelockfile"},
	"verification-metadata.xml":   {"java/gradleverificationmetadataxml"},
	"poetry.lock":                 {"python/poetrylock"},
	"Pipfile.lock":                {"python/Pipfilelock"},
	"pdm.lock":                    {"python/pdmlock"},
	"requirements.txt":            {"python/requirements"},
	"uv.lock":                     {"python/uvlock"},
	"Cargo.lock":                  {"rust/Cargolock"},
	"composer.lock":               {"php/composerlock"},
	"mix.lock":                    {"erlang/mixlock"},
	"renv.lock":                   {"r/renvlock"},
	"deps.json":                   {"dotnet/depsjson"},
	"packages.lock.json":          {"dotnet/packageslockjson"},
	"conan.lock":                  {"cpp/conanlock"},
	"go.mod":                      {"go/gomod"},
	"bun.lock":                    {"javascript/bunlock"},
	"Gemfile.lock":                {"ruby/gemfilelock"},
	"cabal.project.freeze":        {"haskell/cabal"},
	"stack.yaml.lock":             {"haskell/stacklock"},
	// "Package.resolved":            "swift/packageresolved",
}

// ScanSingleFile is similar to ScanSingleFileWithMapping, just without supporting the <lockfileformat>:/path/to/lockfile prefix identifier
func ScanSingleFile(path string, extractorsToUse []filesystem.Extractor) ([]*extractor.Inventory, error) {
	// TODO: Update the logging output to stop referring to SBOMs
	path, err := filepath.Abs(path)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to resolved path %q with error: %s\n", path, err))
		return nil, err
	}

	invs, err := scalibrextract.ExtractWithExtractors(context.Background(), path, extractorsToUse)
	if err != nil {
		slog.Info(fmt.Sprintf("Failed to parse SBOM %q with error: %s\n", path, err))
		return nil, err
	}

	pkgCount := len(invs)
	if pkgCount > 0 {
		slog.Info(fmt.Sprintf(
			"Scanned %s file and found %d %s\n",
			path,
			pkgCount,
			output.Form(pkgCount, "package", "packages"),
		))
	}

	return invs, nil
}

// ScanSingleFileWithMapping will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
func ScanSingleFileWithMapping(scanPath string, extractorsToUse []filesystem.Extractor) ([]*extractor.Inventory, error) {
	var err error
	var inventories []*extractor.Inventory

	parseAs, path := parseLockfilePath(scanPath)

	path, err = filepath.Abs(path)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to resolved path %q with error: %s\n", path, err))
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
		inventories, err = scalibrextract.ExtractWithExtractors(context.Background(), path, extractorsToUse)
	default: // A specific parseAs without a special case is selected
		// Find and extract with the extractor of parseAs
		if names, ok := lockfileExtractorMapping[parseAs]; ok && len(names) > 0 {
			i := slices.IndexFunc(extractorsToUse, func(ext filesystem.Extractor) bool {
				return slices.Contains(names, ext.Name())
			})
			if i < 0 {
				return nil, fmt.Errorf("could not determine extractor, requested %s", parseAs)
			}
			inventories, err = scalibrextract.ExtractWithExtractor(context.Background(), path, extractorsToUse[i])
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

	slog.Info(fmt.Sprintf(
		"Scanned %s file %sand found %d %s\n",
		path,
		parsedAsComment,
		pkgCount,
		output.Form(pkgCount, "package", "packages"),
	))

	return inventories, nil
}

func parseLockfilePath(scanArg string) (string, string) {
	if !strings.Contains(scanArg, ":") {
		scanArg = ":" + scanArg
	}

	splits := strings.SplitN(scanArg, ":", 2)

	return splits[0], splits[1]
}
