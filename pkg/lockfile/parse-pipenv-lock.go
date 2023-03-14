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

	details := make(map[string]PackageDetails)

	addPkgDetails(details, parsedLockfile.Packages)
	addPkgDetails(details, parsedLockfile.PackagesDev)

	return pkgDetailsMapToSlice(details), nil
}

func addPkgDetails(details map[string]PackageDetails, packages map[string]PipenvPackage) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		version := pipenvPackage.Version[2:]

		details[name+"@"+version] = PackageDetails{
			Name:      name,
			Version:   version,
			Ecosystem: PipenvEcosystem,
			CompareAs: PipenvEcosystem,
		}
	}
}
