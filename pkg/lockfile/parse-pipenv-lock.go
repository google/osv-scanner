package lockfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

type PipenvPackage struct {
	Version string `json:"version"`
}

type PipenvLock struct {
	Packages    map[string]PipenvPackage `json:"default"`
	PackagesDev map[string]PipenvPackage `json:"develop"`
}

const PipenvEcosystem = PipEcosystem

type PipenvLockExtractor struct{}

func (e PipenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "Pipfile.lock"
}

func (e PipenvLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *PipenvLock

	err := json.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: %w", f.Path(), err)
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

var _ Extractor = PipenvLockExtractor{}

func ParsePipenvLock(pathToLockfile string) ([]PackageDetails, error) {
	f, err := OpenLocalDepFile(pathToLockfile)

	if err != nil {
		return nil, err
	}

	return PipenvLockExtractor{}.Extract(f)
}
