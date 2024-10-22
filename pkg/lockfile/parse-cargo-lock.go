package lockfile

import (
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type CargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type CargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []CargoLockPackage `toml:"package"`
}

const CargoEcosystem Ecosystem = "crates.io"

type CargoLockExtractor struct{}

func (e CargoLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "Cargo.lock"
}

func (e CargoLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *CargoLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]PackageDetails, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		packages = append(packages, PackageDetails{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Ecosystem: CargoEcosystem,
			CompareAs: CargoEcosystem,
		})
	}

	return packages, nil
}

var _ Extractor = CargoLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("Cargo.lock", CargoLockExtractor{})
}

// Deprecated: use CargoLockExtractor.Extract instead
func ParseCargoLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, CargoLockExtractor{})
}
