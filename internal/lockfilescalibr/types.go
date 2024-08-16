package lockfilescalibr

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/cpp/conanlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/dotnet/nugetpackagelock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/erlang/mixlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/flutter/pubspec"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/go/gomod"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/buildscriptgradlelockfile"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/gradleverificationmetadataxml"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/pomxml"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/packagelockjson"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/pnpmlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/yarnlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/php/composerlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/pdmlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/pipfilelock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/poetrylock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/requirementstxt"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/r/renvlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/ruby/gemfilelock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/rust/cargolock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
)

type PackageDetails struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Commit    string   `json:"commit,omitempty"`
	DepGroups []string `json:"-"`
}

type Ecosystem string

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
	conanlock.Extractor{},
	nugetpackagelock.Extractor{},
	mixlock.Extractor{},
	pubspec.Extractor{},
	gomod.Extractor{},
	pomxml.Extractor{},
	buildscriptgradlelockfile.Extractor{},
	gradleverificationmetadataxml.Extractor{},
	packagelockjson.Extractor{},
	pnpmlock.Extractor{},
	yarnlock.Extractor{},
	composerlock.Extractor{},
	pipfilelock.Extractor{},
	pdmlock.Extractor{},
	poetrylock.Extractor{},
	requirementstxt.Extractor{},
	renvlock.Extractor{},
	gemfilelock.Extractor{},
	cargolock.Extractor{},
}

var lockfileExtractorMapping = map[string]string{
	"pubspec.lock":                "flutter/pubspec",
	"pnpm-lock.yaml":              "javascript/pnpmlock",
	"yarn.lock":                   "javascript/yarnlock",
	"package-lock.json":           "javascript/packagelockjson",
	"pom.xml":                     "java/pomxml",
	"buildscript-gradle.lockfile": "java/buildscriptgradlelockfile",
	"gradle.lockfile":             "java/buildscriptgradlelockfile",
	"verification-metadata.xml":   "java/gradleverificationmetadataxml",
	"poetry.lock":                 "python/poetrylock",
	"Pipfile.lock":                "python/pipfilelock",
	"pdm.lock":                    "python/pdmlock",
	"requirements.txt":            "python/requirementstxt",
	"Cargo.lock":                  "rust/cargolock",
	"composer.lock":               "php/composerlock",
	"mix.lock":                    "erlang/mixlock",
	"renv.lock":                   "r/renvlock",
	"packages.lock.json":          "dotnet/nugetpackagelock",
	"conan.lock":                  "cpp/conanlock",
	"go.mod":                      "go/gomod",
	"Gemfile.lock":                "ruby/gemfilelock",
}

var ErrExtractorNotFound = errors.New("could not determine extractor")

func Extract(ctx context.Context, localPath string, extractAs string) ([]*extractor.Inventory, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return []*extractor.Inventory{}, err
	}

	if extractAs != "" {
		for _, ext := range lockfileExtractors {
			if lockfileExtractorMapping[extractAs] == ext.Name() {
				si, err := createScanInput(localPath, info)
				if err != nil {
					return []*extractor.Inventory{}, err
				}

				inv, err := ext.Extract(ctx, si)
				if err != nil {
					return []*extractor.Inventory{}, fmt.Errorf("(extracting as %s) %w", extractAs, err)
				}
				for i := range inv {
					inv[i].Extractor = ext
				}

				return inv, nil
			}
		}

		return []*extractor.Inventory{}, fmt.Errorf("%w, requested %s", ErrExtractorNotFound, extractAs)
	}

	output := []*extractor.Inventory{}

	for _, ext := range lockfileExtractors {
		if ext.FileRequired(localPath, info) {
			si, err := createScanInput(localPath, info)
			if err != nil {
				return []*extractor.Inventory{}, err
			}

			inv, err := ext.Extract(ctx, si)
			if err != nil {
				return []*extractor.Inventory{}, fmt.Errorf("(extracting as %s) %w", ext.Name(), err)
			}

			for i := range inv {
				inv[i].Extractor = ext
			}
			output = append(output, inv...)
		}
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
		FS:       os.DirFS("/").(plugin.FS),
		Path:     path,
		ScanRoot: "/",
		Reader:   reader,
		Info:     fileInfo,
	}

	return &si, nil
}
