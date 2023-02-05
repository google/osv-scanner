package lockfile

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"io"
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
	return parseFileAndPrintDiag(pathToLockfile, ParseCargoLockFile)
}

func ParseCargoLockFile(pathToLockfile string) ([]PackageDetails, Diagnostics, error) {
	return parseFile(pathToLockfile, ParseCargoLockWithDiagnostics)
}

func ParseCargoLockWithDiagnostics(r io.Reader) ([]PackageDetails, Diagnostics, error) {
	var diag Diagnostics
	var parsedLockfile *CargoLockFile

	_, err := toml.NewDecoder(r).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, diag, fmt.Errorf("could not parse: %w", err)
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

	return packages, diag, nil
}
