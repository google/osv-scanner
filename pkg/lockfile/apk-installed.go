package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

const AlpineEcosystem Ecosystem = "Alpine"

func groupApkPackageLines(scanner *bufio.Scanner) [][]string {
	var groups [][]string
	var group []string

	for scanner.Scan() {
		line := scanner.Text()

		if line != "" {
			group = append(group, line)
			continue
		}
		if len(group) > 0 {
			groups = append(groups, group)
		}
		group = make([]string, 0)
	}

	if len(group) > 0 {
		groups = append(groups, group)
	}

	return groups
}

func parseApkPackageGroup(group []string) PackageDetails {
	var pkg = PackageDetails{
		Ecosystem: AlpineEcosystem,
		CompareAs: AlpineEcosystem,
	}

	// File SPECS: https://wiki.alpinelinux.org/wiki/Apk_spec
	for _, line := range group {
		switch {
		case strings.HasPrefix(line, "P:"):
			pkg.Name = strings.TrimPrefix(line, "P:")
		case strings.HasPrefix(line, "V:"):
			pkg.Version = strings.TrimPrefix(line, "V:")
		case strings.HasPrefix(line, "c:"):
			pkg.Commit = strings.TrimPrefix(line, "c:")
		}
	}

	return pkg
}

func ParseApkInstalled(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, ApkInstalledExtractor{})
}

type ApkInstalledExtractor struct{}

func (e ApkInstalledExtractor) ShouldExtract(path string) bool {
	return path == "/lib/apk/db/installed"
}

func (e ApkInstalledExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	scanner := bufio.NewScanner(f)

	packageGroups := groupApkPackageLines(scanner)

	packages := make([]PackageDetails, 0, len(packageGroups))

	for _, group := range packageGroups {
		pkg := parseApkPackageGroup(group)

		if pkg.Name == "" {
			continue
		}

		packages = append(packages, pkg)
	}

	alpineOSReleaseFile, openErr := f.Open("/etc/os-release")
	if openErr == nil {
		alpineVersion, extractErr := osReleaseVersionExtractor(alpineOSReleaseFile)
		if extractErr != nil {
			return packages, fmt.Errorf("error while parsing /etc/os-release: %w", extractErr)
		}

		if alpineVersion != "" {
			for i := range packages {
				packages[i].Ecosystem = Ecosystem(string(packages[i].Ecosystem) + ":" + alpineVersion)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	return packages, nil
}

// osReleaseVersionExtractor extracts the release version for an alpine distro
// will return "" if no release version can be found, or if distro is not alpine
func osReleaseVersionExtractor(releaseReader io.Reader) (string, error) {
	scanner := bufio.NewScanner(releaseReader)
	returnVersion := ""
	isAlpine := false

	for scanner.Scan() {
		key, value, isEntry := strings.Cut(scanner.Text(), "=")
		if !isEntry {
			continue
		}

		if key == "ID" {
			value = strings.Trim(value, "\"")
			isAlpine = value == "alpine"
		}

		if key == "VERSION_ID" {
			value = strings.Trim(value, "\"")
			// We only care about the major and minor version
			// because that's the Alpine version that advisories are published against
			//
			// E.g. VERSION_ID=3.20.0_alpha20231219
			valueSplit := strings.Split(value, ".")
			returnVersion = valueSplit[0] + "." + valueSplit[1]

			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if !isAlpine {
		returnVersion = ""
	}

	return returnVersion, nil
}

var _ Extractor = ApkInstalledExtractor{}

// FromApkInstalled attempts to parse the given file as an "apk-installed" lockfile
// used by the Alpine Package Keeper (apk) to record installed packages.
func FromApkInstalled(pathToInstalled string) (Lockfile, error) {
	packages, err := ParseApkInstalled(pathToInstalled)

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return Lockfile{
		FilePath: pathToInstalled,
		ParsedAs: "apk-installed",
		Packages: packages,
	}, err
}
