package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const AlpineEcosystem Ecosystem = "Alpine"

func groupApkPackageLines(scanner *bufio.Scanner) [][]string {
	var groups [][]string
	var group []string

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if len(group) > 0 {
				groups = append(groups, group)
			}
			group = make([]string, 0)
			continue
		}
		group = append(group, line)
	}

	if len(group) > 0 {
		groups = append(groups, group)
	}

	return groups
}

func parseApkPackageGroup(group []string, pathToLockfile string) (PackageDetails, error) {
	var pkg PackageDetails = PackageDetails{}

	// File SPECS: https://wiki.alpinelinux.org/wiki/Apk_spec
	for _, line := range group {
		switch {
		case strings.HasPrefix(line, "P:"):
			pkg.Name = strings.TrimPrefix(line, "P:")
			pkg.Ecosystem = AlpineEcosystem
			pkg.CompareAs = AlpineEcosystem
		case strings.HasPrefix(line, "V:"):
			pkg.Version = strings.TrimPrefix(line, "V:")
		case strings.HasPrefix(line, "c:"):
			pkg.Commit = strings.TrimPrefix(line, "c:")
		}
	}

	if pkg.Name == "" {
		return PackageDetails{}, fmt.Errorf("warning: malformed APK installed file. Found no version number in record. File: %s", pathToLockfile)
	}
	if pkg.Version == "" {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"warning: malformed APK installed file. Found no version number in record. File: %s\n",
			pathToLockfile,
		)
	}

	return pkg, nil
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
		if pkg, err := parseApkPackageGroup(group, pathToLockfile); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		} else {
			packages = append(packages, pkg)
		}
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning %s: %w", pathToLockfile, err)
	}

	return packages, nil
}
