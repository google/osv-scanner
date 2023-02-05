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

func parseApkPackageGroup(diag *Diagnostics, group []string) PackageDetails {
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

		diag.Warn(fmt.Sprintf(
			"malformed APK installed file - found no version number in record for %s",
			pkgPrintName,
		))
	}

	return pkg
}

func ParseApkInstalled(pathToLockfile string) ([]PackageDetails, error) {
	return parseFileAndPrintDiag(pathToLockfile, ParseApkInstalledFile)
}

func ParseApkInstalledFile(pathToLockfile string) ([]PackageDetails, Diagnostics, error) {
	return parseFile(pathToLockfile, ParseApkInstalledWithDiagnostics)
}

func ParseApkInstalledWithDiagnostics(r io.Reader) ([]PackageDetails, Diagnostics, error) {
	var diag Diagnostics

	scanner := bufio.NewScanner(r)

	packageGroups := groupApkPackageLines(scanner)

	packages := make([]PackageDetails, 0, len(packageGroups))

	for _, group := range packageGroups {
		pkg := parseApkPackageGroup(&diag, group)

		if pkg.Name == "" {
			diag.Warn("malformed APK installed file - found no package name in record")

			continue
		}

		packages = append(packages, pkg)
	}

	if err := scanner.Err(); err != nil {
		return packages, diag, fmt.Errorf("error while scanning: %w", err)
	}

	return packages, diag, nil
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
