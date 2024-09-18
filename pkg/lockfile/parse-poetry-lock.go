package lockfile

import (
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type PoetryLockPackageSource struct {
	Type   string `toml:"type"`
	Commit string `toml:"resolved_reference"`
}

type PoetryLockPackage struct {
	Name     string                  `toml:"name"`
	Version  string                  `toml:"version"`
	Optional bool                    `toml:"optional"`
	Source   PoetryLockPackageSource `toml:"source"`
}

type PoetryLockFile struct {
	Version  int                 `toml:"version"`
	Packages []PoetryLockPackage `toml:"package"`
}

const PoetryEcosystem = PipEcosystem

type PoetryLockExtractor struct{}

func (e PoetryLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "poetry.lock"
}

func (e PoetryLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *PoetryLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]PackageDetails, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		pkgDetails := PackageDetails{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Commit:    lockPackage.Source.Commit,
			Ecosystem: PoetryEcosystem,
			CompareAs: PoetryEcosystem,
		}
		if lockPackage.Optional {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, "optional")
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

var _ Extractor = PoetryLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("poetry.lock", PoetryLockExtractor{})
}

// Deprecated: use PoetryLockExtractor.Extract instead
func ParsePoetryLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, PoetryLockExtractor{})
}
