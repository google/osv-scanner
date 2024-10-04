package lockfilescalibr

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleverificationmetadataxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/yarnlock"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
// func (sys Ecosystem) IsDevGroup(groups []string) bool {
// 	dev := ""
// 	switch sys {
// 	case ComposerEcosystem, NpmEcosystem, PipEcosystem, PubEcosystem:
// 		// Also PnpmEcosystem(=NpmEcosystem) and PipenvEcosystem(=PipEcosystem).
// 		dev = "dev"
// 	case ConanEcosystem:
// 		dev = "build-requires"
// 	case MavenEcosystem:
// 		dev = "test"
// 	case AlpineEcosystem, BundlerEcosystem, CargoEcosystem, CRANEcosystem,
// 		DebianEcosystem, GoEcosystem, MixEcosystem, NuGetEcosystem:
// 		// We are not able to report development dependencies for these ecosystems.
// 		return false
// 	}

// 	for _, g := range groups {
// 		if g == dev {
// 			return true
// 		}
// 	}

// 	return false
// }

var lockfileExtractors = []filesystem.Extractor{
	// conanlock.Extractor{},
	// nugetpackagelock.Extractor{},
	mixlock.Extractor{},
	// pubspec.Extractor{},
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
	// "pubspec.lock":   "flutter/pubspec",
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
	// "packages.lock.json":          "dotnet/nugetpackagelock",
	// "conan.lock":                  "cpp/conanlock",
	"go.mod":       "go/gomod",
	"Gemfile.lock": "ruby/gemfilelock",
}

func ExtractWithExtractor(ctx context.Context, localPath string, ext filesystem.Extractor) ([]*extractor.Inventory, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}

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

func Extract(ctx context.Context, localPath string, extractAs string) ([]*extractor.Inventory, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}

	if extractAs != "" {
		for _, ext := range lockfileExtractors {
			if lockfileExtractorMapping[extractAs] == ext.Name() {
				si, err := createScanInput(localPath, info)
				if err != nil {
					return nil, err
				}

				inv, err := ext.Extract(ctx, si)
				if err != nil {
					return nil, fmt.Errorf("(extracting as %s) %w", extractAs, err)
				}

				for i := range inv {
					inv[i].Extractor = ext
				}

				return inv, nil
			}
		}

		return nil, fmt.Errorf("%w, requested %s", ErrExtractorNotFound, extractAs)
	}

	output := []*extractor.Inventory{}
	extractorFound := false

	for _, ext := range lockfileExtractors {
		if ext.FileRequired(localPath, info) {
			extractorFound = true
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
