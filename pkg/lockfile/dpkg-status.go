package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const DebianEcosystem Ecosystem = "Debian"

func groupDpkgPackageLines(scanner *bufio.Scanner) [][]string {
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

func parseDpkgPackageGroup(group []string, pathToLockfile string) PackageDetails {
	var pkg = PackageDetails{
		Ecosystem: DebianEcosystem,
		CompareAs: DebianEcosystem,
	}

	// TODO File SPECS:
	for _, line := range group {
		switch {
		case strings.HasPrefix(line, "Package:"):
			pkg.Name = strings.TrimPrefix(line, "Package:")
			pkg.Name = strings.TrimSpace(pkg.Name)
		case strings.HasPrefix(line, "Version:"):
			pkg.Version = strings.TrimPrefix(line, "Version:")
			pkg.Version = strings.TrimSpace(pkg.Version)
		}
	}

	if pkg.Version == "" {
		pkgPrintName := pkg.Name
		if pkgPrintName == "" {
			pkgPrintName = "<unknown>"
		}

		_, _ = fmt.Fprintf(
			os.Stderr,
			"warning: malformed DPKG status file. Found no version number in record. Package %s. File: %s\n",
			pkgPrintName,
			pathToLockfile,
		)
	}

	return pkg
}

func ParseDpkgStatus(pathToLockfile string) ([]PackageDetails, error) {
	file, err := os.Open(pathToLockfile)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not open %s: %w", pathToLockfile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packageGroups := groupDpkgPackageLines(scanner)

	packages := make([]PackageDetails, 0, len(packageGroups))

	for _, group := range packageGroups {
		pkg := parseDpkgPackageGroup(group, pathToLockfile)

		if pkg.Name == "" {
			_, _ = fmt.Fprintf(
				os.Stderr,
				"warning: malformed DPKG status file. Found no package name in record. File: %s\n",
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
