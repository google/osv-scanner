package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
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

func ParseComposerLock(pathToLockfile string) ([]PackageDetails, error) {
	var parsedLockfile *ComposerLock

	lockfileContents, err := os.ReadFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	err = json.Unmarshal(lockfileContents, &parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: %w", pathToLockfile, err)
	}

	packages := make(
		[]PackageDetails,
		0,
		// len cannot return negative numbers, but the types can't reflect that
		uint64(len(parsedLockfile.Packages))+uint64(len(parsedLockfile.PackagesDev)),
	)

	for _, composerPackage := range parsedLockfile.Packages {
		packages = append(packages, PackageDetails{
			Name:      composerPackage.Name,
			Version:   composerPackage.Version,
			Commit:    composerPackage.Dist.Reference,
			Ecosystem: ComposerEcosystem,
			CompareAs: ComposerEcosystem,
		})
	}

	for _, composerPackage := range parsedLockfile.PackagesDev {
		packages = append(packages, PackageDetails{
			Name:      composerPackage.Name,
			Version:   composerPackage.Version,
			Commit:    composerPackage.Dist.Reference,
			Ecosystem: ComposerEcosystem,
			CompareAs: ComposerEcosystem,
		})
	}

	return packages, nil
}
