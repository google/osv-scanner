package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
)

type PipenvPackage struct {
	Version string `json:"version"`
}

type PipenvLock struct {
	Packages    map[string]PipenvPackage `json:"default"`
	PackagesDev map[string]PipenvPackage `json:"develop"`
}

const PipenvEcosystem = PipEcosystem

func ParsePipenvLock(pathToLockfile string) ([]PackageDetails, error) {
	var parsedLockfile *PipenvLock

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

	for name, pipenvPackage := range parsedLockfile.Packages {
		if pipenvPackage.Version == "" {
			continue
		}

		packages = append(packages, PackageDetails{
			Name:      name,
			Version:   pipenvPackage.Version[2:],
			Ecosystem: PipenvEcosystem,
			CompareAs: PipenvEcosystem,
		})
	}

	for name, pipenvPackage := range parsedLockfile.PackagesDev {
		packages = append(packages, PackageDetails{
			Name:      name,
			Version:   pipenvPackage.Version[2:],
			Ecosystem: PipenvEcosystem,
			CompareAs: PipenvEcosystem,
		})
	}

	return packages, nil
}
