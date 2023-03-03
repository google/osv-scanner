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

	packages := make(map[string]PackageDetails)

	for name, pipenvPackage := range parsedLockfile.Packages {
		if pipenvPackage.Version == "" {
			continue
		}

		version := pipenvPackage.Version[2:]

		packages[name+"@"+version] = PackageDetails{
			Name:      name,
			Version:   version,
			Ecosystem: PipenvEcosystem,
			CompareAs: PipenvEcosystem,
		}
	}

	for name, pipenvPackage := range parsedLockfile.PackagesDev {
		version := pipenvPackage.Version[2:]

		packages[name+"@"+version] = PackageDetails{
			Name:      name,
			Version:   version,
			Ecosystem: PipenvEcosystem,
			CompareAs: PipenvEcosystem,
		}
	}

	return pkgDetailsMapToSlice(packages), nil
}
