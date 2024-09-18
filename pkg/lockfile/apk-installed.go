package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

const AlpineEcosystem Ecosystem = "Alpine"
const AlpineFallbackVersion = "v3.20"

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

// Deprecated: use ApkInstalledExtractor.Extract instead
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

	alpineVersion, alpineVerErr := alpineReleaseExtractor(f)
	if alpineVerErr != nil { // TODO: Log error? We might not be on a alpine system
		// Alpine ecosystems MUST have a version suffix. Fallback to the latest version.
		alpineVersion = AlpineFallbackVersion
	}
	for i := range packages {
		packages[i].Ecosystem = Ecosystem(string(packages[i].Ecosystem) + ":" + alpineVersion)
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	return packages, nil
}

// alpineReleaseExtractor extracts the release version for an alpine distro
// will return "" if no release version can be found, or if distro is not alpine
func alpineReleaseExtractor(opener DepFile) (string, error) {
	alpineReleaseFile, err := opener.Open("/etc/alpine-release")
	if err != nil {
		return "", err
	}
	defer alpineReleaseFile.Close()

	// Read to string
	buf := new(strings.Builder)
	_, err = io.Copy(buf, alpineReleaseFile)
	if err != nil {
		return "", err
	}

	// We only care about the major and minor version
	// because that's the Alpine version that advisories are published against
	//
	// E.g. 3.20.0_alpha20231219  --->  v3.20
	valueSplit := strings.Split(buf.String(), ".")
	returnVersion := "v" + valueSplit[0] + "." + valueSplit[1]

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
