package lockfile

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"os"
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

func ParseCargoLock(pathToLockfile string) ([]PackageDetails, error) {
	var parsedLockfile *CargoLockFile

	lockfileContents, err := os.ReadFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	err = toml.Unmarshal(lockfileContents, &parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: %w", pathToLockfile, err)
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
