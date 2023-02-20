package lockfile

import (
	"bufio"
	"fmt"
	"os"
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

func parseApkPackageGroup(group []string, pathToLockfile string) PackageDetails {
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

	if pkg.Version == "" {
		pkgPrintName := pkg.Name
		if pkgPrintName == "" {
			pkgPrintName = unknownPkgName
		}

		_, _ = fmt.Fprintf(
			os.Stderr,
			"warning: malformed APK installed file. Found no version number in record. Package %s. File: %s\n",
			pkgPrintName,
			pathToLockfile,
		)
	}

	return pkg
}

func ParseApkInstalled(pathToLockfile string) ([]PackageDetails, error) {
	file, err := os.Open(pathToLockfile)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not open %s: %w", pathToLockfile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	packageGroups := groupApkPackageLines(scanner)

	packages := make([]PackageDetails, 0, len(packageGroups))

	for _, group := range packageGroups {
		pkg := parseApkPackageGroup(group, pathToLockfile)

		if pkg.Name == "" {
			_, _ = fmt.Fprintf(
				os.Stderr,
				"warning: malformed APK installed file. Found no package name in record. File: %s\n",
				pathToLockfile,
			)

			continue
		}

		packages = append(packages, pkg)
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning %s: %w", pathToLockfile, err)
	}

	return packages, nil
}

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
