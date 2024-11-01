package lockfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/google/osv-scanner/pkg/models"
)

type ComposerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Reference string `json:"reference"`
	} `json:"dist"`
}

type ComposerLock struct {
	Packages    []ComposerPackage `json:"packages"`
	PackagesDev []ComposerPackage `json:"packages-dev"`
}

const ComposerEcosystem Ecosystem = "Packagist"

type ComposerLockExtractor struct {
	WithMatcher
}

func (e ComposerLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "composer.lock"
}

func (e ComposerLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *ComposerLock

	err := json.NewDecoder(f).Decode(&parsedLockfile)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make(
		[]PackageDetails,
		0,
		// len cannot return negative numbers, but the types can't reflect that
		uint64(len(parsedLockfile.Packages))+uint64(len(parsedLockfile.PackagesDev)),
	)

	for _, composerPackage := range parsedLockfile.Packages {
		packages = append(packages, PackageDetails{
			Name:           composerPackage.Name,
			Version:        composerPackage.Version,
			Commit:         composerPackage.Dist.Reference,
			PackageManager: models.Composer,
			Ecosystem:      ComposerEcosystem,
			CompareAs:      ComposerEcosystem,
		})
	}

	for _, composerPackage := range parsedLockfile.PackagesDev {
		packages = append(packages, PackageDetails{
			Name:           composerPackage.Name,
			Version:        composerPackage.Version,
			Commit:         composerPackage.Dist.Reference,
			PackageManager: models.Composer,
			Ecosystem:      ComposerEcosystem,
			CompareAs:      ComposerEcosystem,
			DepGroups:      []string{"dev"},
		})
	}

	return packages, nil
}

var ComposerExtractor = ComposerLockExtractor{
	WithMatcher{Matcher: ComposerMatcher{}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("composer.lock", ComposerExtractor)
}

func ParseComposerLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, ComposerExtractor)
}
