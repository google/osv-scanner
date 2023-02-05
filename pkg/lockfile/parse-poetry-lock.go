package lockfile

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"io"
)

type PoetryLockPackageSource struct {
	Type   string `toml:"type"`
	Commit string `toml:"resolved_reference"`
}

type PoetryLockPackage struct {
	Name    string                  `toml:"name"`
	Version string                  `toml:"version"`
	Source  PoetryLockPackageSource `toml:"source"`
}

type PoetryLockFile struct {
	Version  int                 `toml:"version"`
	Packages []PoetryLockPackage `toml:"package"`
}

const PoetryEcosystem = PipEcosystem

func ParsePoetryLock(pathToLockfile string) ([]PackageDetails, error) {
	return parseFileAndPrintDiag(pathToLockfile, ParsePoetryLockFile)
}

func ParsePoetryLockFile(pathToLockfile string) ([]PackageDetails, Diagnostics, error) {
	return parseFile(pathToLockfile, ParsePoetryLockWithDiagnostics)
}

func ParsePoetryLockWithDiagnostics(r io.Reader) ([]PackageDetails, Diagnostics, error) {
	var parsedLockfile *PoetryLockFile
	var diag Diagnostics

	_, err := toml.NewDecoder(r).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, diag, fmt.Errorf("could not parse: %w", err)
	}

	packages := make([]PackageDetails, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		packages = append(packages, PackageDetails{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Commit:    lockPackage.Source.Commit,
			Ecosystem: PoetryEcosystem,
			CompareAs: PoetryEcosystem,
		})
	}

	return packages, diag, nil
}
