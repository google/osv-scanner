package lockfile

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"os"
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
	var parsedLockfile *PoetryLockFile

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
			Commit:    lockPackage.Source.Commit,
			Ecosystem: PoetryEcosystem,
			CompareAs: PoetryEcosystem,
		})
	}

	return packages, nil
}
