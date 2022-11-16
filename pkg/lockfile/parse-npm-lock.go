package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
)

type NpmLockDependency struct {
	Version      string                       `json:"version"`
	Dependencies map[string]NpmLockDependency `json:"dependencies,omitempty"`
}

type NpmLockPackage struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
}

type NpmLockfile struct {
	Version int `json:"lockfileVersion"`
	// npm v1- lockfiles use "dependencies"
	Dependencies map[string]NpmLockDependency `json:"dependencies"`
	// npm v2+ lockfiles use "packages"
	Packages map[string]NpmLockPackage `json:"packages,omitempty"`
}

const NpmEcosystem Ecosystem = "npm"

func pkgDetailsMapToSlice(m map[string]PackageDetails) []PackageDetails {
	details := make([]PackageDetails, 0, len(m))

	for _, detail := range m {
		details = append(details, detail)
	}

	return details
}

func mergePkgDetailsMap(m1 map[string]PackageDetails, m2 map[string]PackageDetails) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	for name, detail := range m1 {
		details[name] = detail
	}

	for name, detail := range m2 {
		details[name] = detail
	}

	return details
}

func parseNpmLockDependencies(dependencies map[string]NpmLockDependency) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	for name, detail := range dependencies {
		if detail.Dependencies != nil {
			details = mergePkgDetailsMap(details, parseNpmLockDependencies(detail.Dependencies))
		}

		version := detail.Version
		finalVersion := version
		commit := ""

		// we can't resolve a version from a "file:" dependency
		if strings.HasPrefix(detail.Version, "file:") {
			finalVersion = ""
		} else {
			commit = tryExtractCommit(detail.Version)

			// if there is a commit, we want to deduplicate based on that rather than
			// the version (the versions must match anyway for the commits to match)
			//
			// we also don't actually know what the "version" is, so blank it
			if commit != "" {
				finalVersion = ""
				version = commit
			}
		}

		details[name+"@"+version] = PackageDetails{
			Name:      name,
			Version:   finalVersion,
			Ecosystem: NpmEcosystem,
			CompareAs: NpmEcosystem,
			Commit:    commit,
		}
	}

	return details
}

func extractNpmPackageName(name string) string {
	maybeScope := path.Base(path.Dir(name))
	pkgName := path.Base(name)

	if strings.HasPrefix(maybeScope, "@") {
		pkgName = maybeScope + "/" + pkgName
	}

	return pkgName
}

func parseNpmLockPackages(packages map[string]NpmLockPackage) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	for namePath, detail := range packages {
		if namePath == "" {
			continue
		}
		finalName := extractNpmPackageName(namePath)
		finalVersion := detail.Version

		commit := tryExtractCommit(detail.Resolved)

		// if there is a commit, we want to deduplicate based on that rather than
		// the version (the versions must match anyway for the commits to match)
		if commit != "" {
			finalVersion = commit
		}

		details[finalName+"@"+finalVersion] = PackageDetails{
			Name:      finalName,
			Version:   detail.Version,
			Ecosystem: NpmEcosystem,
			CompareAs: NpmEcosystem,
			Commit:    commit,
		}
	}

	return details
}

func parseNpmLock(lockfile NpmLockfile) map[string]PackageDetails {
	if lockfile.Packages != nil {
		return parseNpmLockPackages(lockfile.Packages)
	}

	return parseNpmLockDependencies(lockfile.Dependencies)
}

func ParseNpmLock(pathToLockfile string) ([]PackageDetails, error) {
	var parsedLockfile *NpmLockfile

	lockfileContents, err := os.ReadFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	err = json.Unmarshal(lockfileContents, &parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: %w", pathToLockfile, err)
	}

	return pkgDetailsMapToSlice(parseNpmLock(*parsedLockfile)), nil
}
