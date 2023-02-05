package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
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

func parseNuGetLock(lockfile NuGetLockfile) ([]PackageDetails, Diagnostics, error) {
	var details = map[string]PackageDetails{}
	var diag Diagnostics

	// go through the dependencies for each framework, e.g. `net6.0` and parse
	// its dependencies, there might be different or duplicate dependencies
	// between frameworks
	for _, dependencies := range lockfile.Dependencies {
		details = mergePkgDetailsMap(details, parseNuGetLockDependencies(dependencies))
	}

	return pkgDetailsMapToSlice(details), diag, nil
}

func ParseNuGetLock(pathToLockfile string) ([]PackageDetails, error) {
	return parseFileAndPrintDiag(pathToLockfile, ParseNuGetLockFile)
}

func ParseNuGetLockFile(pathToLockfile string) ([]PackageDetails, Diagnostics, error) {
	return parseFile(pathToLockfile, ParseNuGetLockWithDiagnostics)
}

func ParseNuGetLockWithDiagnostics(r io.Reader) ([]PackageDetails, Diagnostics, error) {
	var parsedLockfile *NuGetLockfile
	var diag Diagnostics

	err := json.NewDecoder(r).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, diag, fmt.Errorf("could not parse: %w", err)
	}

	if parsedLockfile.Version != 1 {
		return []PackageDetails{}, diag, fmt.Errorf("unsupported lock file version")
	}

	return parseNuGetLock(*parsedLockfile)
}
