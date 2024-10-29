package lockfilescalibr

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
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

	scalibrfs "github.com/google/osv-scalibr/fs"
)

var lockfileExtractors = []filesystem.Extractor{
	// conanlock.Extractor{},
	packageslockjson.Extractor{},
	mixlock.Extractor{},
	pubspec.Extractor{},
	gomod.Extractor{},
	pomxml.Extractor{},
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
	"pubspec.lock":                "dart/pubspec",
	"pnpm-lock.yaml":              "javascript/pnpmlock",
	"yarn.lock":                   "javascript/yarnlock",
	"package-lock.json":           "javascript/packagelockjson",
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
	// "conan.lock":                  "cpp/conanlock",
	"go.mod":       "go/gomod",
	"Gemfile.lock": "ruby/gemfilelock",
}

// ExtractWithExtractor attempts to extract the file at the given path with the extractor passed in
func ExtractWithExtractor(ctx context.Context, localPath string, ext filesystem.Extractor) ([]*extractor.Inventory, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}

	return extractWithExtractor(ctx, localPath, info, ext)
}

// Extract attempts to extract the file at the given path
//
// Args:
//   - localPath: the path to the lockfile
//   - extractAs: the name of the lockfile format to extract as (Using OSV-Scanner V1 extractor names)
//
// Returns:
//   - []*extractor.Inventory: the extracted lockfile data
//   - error: any errors encountered during extraction
//
// If extractAs is not specified, then the function will attempt to
// identify the lockfile format based on the file name.
//
// If no extractors are found, then ErrNoExtractorsFound is returned.
func Extract(ctx context.Context, localPath string, extractAs string) ([]*extractor.Inventory, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}

	if extractAs != "" {
		return extractAsSpecific(ctx, extractAs, localPath, info)
	}

	output := []*extractor.Inventory{}
	extractorFound := false

	for _, ext := range lockfileExtractors {
		if ext.FileRequired(localPath, info) {
			extractorFound = true

			inv, err := extractWithExtractor(ctx, localPath, info, ext)
			if err != nil {
				return nil, err
			}

			output = append(output, inv...)
		}
	}

	if !extractorFound {
		return nil, ErrNoExtractorsFound
	}

	sort.Slice(output, func(i, j int) bool {
		if output[i].Name == output[j].Name {
			return output[i].Version < output[j].Version
		}

		return output[i].Name < output[j].Name
	})

	return output, nil
}

// Use the extractor specified by extractAs string key
func extractAsSpecific(ctx context.Context, extractAs string, localPath string, info fs.FileInfo) ([]*extractor.Inventory, error) {
	for _, ext := range lockfileExtractors {
		if lockfileExtractorMapping[extractAs] == ext.Name() {
			return extractWithExtractor(ctx, localPath, info, ext)
		}
	}

	return nil, fmt.Errorf("%w, requested %s", ErrExtractorNotFound, extractAs)
}

func extractWithExtractor(ctx context.Context, localPath string, info fs.FileInfo, ext filesystem.Extractor) ([]*extractor.Inventory, error) {
	si, err := createScanInput(localPath, info)
	if err != nil {
		return nil, err
	}

	inv, err := ext.Extract(ctx, si)
	if err != nil {
		return nil, fmt.Errorf("(extracting as %s) %w", ext.Name(), err)
	}

	for i := range inv {
		inv[i].Extractor = ext
	}

	return inv, nil
}

func createScanInput(path string, fileInfo fs.FileInfo) (*filesystem.ScanInput, error) {
	reader, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	si := filesystem.ScanInput{
		FS:     os.DirFS("/").(scalibrfs.FS),
		Path:   path,
		Root:   "/",
		Reader: reader,
		Info:   fileInfo,
	}

	return &si, nil
}
