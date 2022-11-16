package lockfile

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
	"regexp"
	"strings"
)

type PnpmLockPackageResolution struct {
	Tarball string `yaml:"tarball"`
	Commit  string `yaml:"commit"`
	Repo    string `yaml:"repo"`
	Type    string `yaml:"type"`
}

type PnpmLockPackage struct {
	Resolution PnpmLockPackageResolution `yaml:"resolution"`
	Name       string                    `yaml:"name"`
	Version    string                    `yaml:"version"`
}

type PnpmLockfile struct {
	Version  float64                    `yaml:"lockfileVersion"`
	Packages map[string]PnpmLockPackage `yaml:"packages,omitempty"`
}

const PnpmEcosystem = NpmEcosystem

func startsWithNumber(str string) bool {
	matcher := regexp.MustCompile(`^\d`)

	return matcher.MatchString(str)
}

// extractPnpmPackageNameAndVersion parses a dependency path, attempting to
// extract the name and version of the package it represents
func extractPnpmPackageNameAndVersion(dependencyPath string) (string, string) {
	parts := strings.Split(dependencyPath, "/")
	var name string

	parts = parts[1:]

	if strings.HasPrefix(parts[0], "@") {
		name = strings.Join(parts[:2], "/")
		parts = parts[2:]
	} else {
		name = parts[0]
		parts = parts[1:]
	}

	version := ""

	if len(parts) != 0 {
		version = parts[0]
	}

	if version == "" || !startsWithNumber(version) {
		return "", ""
	}

	underscoreIndex := strings.Index(version, "_")

	if underscoreIndex != -1 {
		version = strings.Split(version, "_")[0]
	}

	return name, version
}

func parsePnpmLock(lockfile PnpmLockfile) []PackageDetails {
	packages := make([]PackageDetails, 0, len(lockfile.Packages))

	for s, pkg := range lockfile.Packages {
		name, version := extractPnpmPackageNameAndVersion(s)

		// "name" is only present if it's not in the dependency path and takes
		// priority over whatever name we think we've extracted (if any)
		if pkg.Name != "" {
			name = pkg.Name
		}

		// "version" is only present if it's not in the dependency path and takes
		// priority over whatever version we think we've extracted (if any)
		if pkg.Version != "" {
			version = pkg.Version
		}

		if name == "" || version == "" {
			continue
		}

		commit := pkg.Resolution.Commit

		if strings.HasPrefix(pkg.Resolution.Tarball, "https://codeload.github.com") {
			re := regexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`)
			matched := re.FindStringSubmatch(pkg.Resolution.Tarball)

			if matched != nil {
				commit = matched[1]
			}
		}

		packages = append(packages, PackageDetails{
			Name:      name,
			Version:   version,
			Ecosystem: PnpmEcosystem,
			CompareAs: PnpmEcosystem,
			Commit:    commit,
		})
	}

	return packages
}

func ParsePnpmLock(pathToLockfile string) ([]PackageDetails, error) {
	var parsedLockfile *PnpmLockfile

	lockfileContents, err := os.ReadFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	err = yaml.Unmarshal(lockfileContents, &parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: %w", pathToLockfile, err)
	}

	return parsePnpmLock(*parsedLockfile), nil
}
