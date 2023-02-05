package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
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
	return parseFileAndPrintDiag(pathToLockfile, ParsePipenvLockFile)
}

func ParsePipenvLockFile(pathToLockfile string) ([]PackageDetails, Diagnostics, error) {
	return parseFile(pathToLockfile, ParsePipenvLockWithDiagnostics)
}

func ParsePipenvLockWithDiagnostics(r io.Reader) ([]PackageDetails, Diagnostics, error) {
	var parsedLockfile *PipenvLock
	var diag Diagnostics

	err := json.NewDecoder(r).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, diag, fmt.Errorf("could not parse: %w", err)
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

	return pkgDetailsMapToSlice(packages), diag, nil
}
