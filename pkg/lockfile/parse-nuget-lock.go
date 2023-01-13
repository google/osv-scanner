package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
)

type NuGetLockPackage struct {
	Resolved string `json:"resolved"`
}

// NuGetLockfile contains the required dependency information as defined in
// https://github.com/NuGet/NuGet.Client/blob/6.5.0.136/src/NuGet.Core/NuGet.ProjectModel/ProjectLockFile/PackagesLockFileFormat.cs
type NuGetLockfile struct {
	Version      int                                    `json:"version"`
	Dependencies map[string]map[string]NuGetLockPackage `json:"dependencies"`
}

const NuGetEcosystem Ecosystem = "NuGet"

func parseNuGetLockDependencies(dependencies map[string]NuGetLockPackage) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	for name, dependency := range dependencies {
		details[name+"@"+dependency.Resolved] = PackageDetails{
			Name:      name,
			Version:   dependency.Resolved,
			Ecosystem: NuGetEcosystem,
			CompareAs: NuGetEcosystem,
		}
	}

	return details
}

func parseNuGetLock(lockfile NuGetLockfile) ([]PackageDetails, error) {
	details := map[string]PackageDetails{}

	// go through the dependencies for each framework, e.g. `net6.0` and parse
	// its dependencies, there might be different or duplicate dependencies
	// between frameworks
	for _, dependencies := range lockfile.Dependencies {
		details = mergePkgDetailsMap(details, parseNuGetLockDependencies(dependencies))
	}

	return pkgDetailsMapToSlice(details), nil
}

func ParseNuGetLock(pathToLockfile string) ([]PackageDetails, error) {
	var parsedLockfile *NuGetLockfile

	lockfileContents, err := os.ReadFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	err = json.Unmarshal(lockfileContents, &parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: %w", pathToLockfile, err)
	}

	if parsedLockfile.Version != 1 {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: unsupported lock file version", pathToLockfile)
	}

	return parseNuGetLock(*parsedLockfile)
}
