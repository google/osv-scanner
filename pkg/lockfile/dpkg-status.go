package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

const DebianEcosystem Ecosystem = "Debian"

func groupDpkgPackageLines(scanner *bufio.Scanner) [][]string {
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

// Return name and version if "Source" field contains them
func parseSourceField(source string) (string, string) {
	// Pattern: name (version)
	re := regexp.MustCompile(`^(.*)\((.*)\)`)
	matches := re.FindStringSubmatch(source)
	if len(matches) == 3 {
		return strings.TrimSpace(matches[1]), strings.TrimSpace(matches[2])
	}
	// If it not matches the pattern "name (version)", it is only "name"
	return strings.TrimSpace(source), ""
}

func parseDpkgPackageGroup(group []string, pathToLockfile string) PackageDetails {
	var pkg = PackageDetails{
		Ecosystem: DebianEcosystem,
		CompareAs: DebianEcosystem,
	}

	sourcePresent := false
	sourceHasVersion := false
	for _, line := range group {
		switch {
		// Status field SPECS: http://www.fifi.org/doc/libapt-pkg-doc/dpkg-tech.html/ch1.html#s1.2
		case strings.HasPrefix(line, "Status:"):
			status := strings.TrimPrefix(line, "Status:")
			tokens := strings.Fields(status)
			// Staus field is malformed. Expected: "Status: Want Flag Status"
			if len(tokens) != 3 {
				_, _ = fmt.Fprintf(
					os.Stderr,
					"warning: malformed DPKG status file. Found no valid \"Source\" field. File: %s\n",
					pathToLockfile,
				)

				return PackageDetails{}
			}
			// Status field has correct number of fields but package is not installed or has only config files left
			// various other field values indicate partial install/uninstall (e.g. failure of some pre/post install scripts)
			// since it's not clear if failure has left package active on system, cautiously add it to queries to osv.dev
			if tokens[2] == "not-installed" || tokens[2] == "config-files" {
				return PackageDetails{}
			}

		case strings.HasPrefix(line, "Source:"):
			sourcePresent = true
			source := strings.TrimPrefix(line, "Source:")
			name, version := parseSourceField(source)
			pkg.Name = name // can be ""
			if version != "" {
				sourceHasVersion = true
				pkg.Version = version
			}

		// If Source field has no version, use Version field
		case strings.HasPrefix(line, "Version:"):
			if !sourceHasVersion {
				pkg.Version = strings.TrimPrefix(line, "Version:")
				pkg.Version = strings.TrimSpace(pkg.Version)
			}

		// Some packages have no Source field (e.g. sudo) so we use Package value
		case strings.HasPrefix(line, "Package:"):
			if !sourcePresent {
				pkg.Name = strings.TrimPrefix(line, "Package:")
				pkg.Name = strings.TrimSpace(pkg.Name)
			}
		}
	}

	if pkg.Version == "" {
		pkgPrintName := pkg.Name
		if pkgPrintName == "" {
			pkgPrintName = unknownPkgName
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

		// PackageDetails does not contain any field that represent a "not installed" state
		// To manage this state and avoid false positives, empty struct means "not installed" so skip it
		if (PackageDetails{}) == pkg {
			continue
		}

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

// FromDpkgStatus attempts to parse the given file as an "dpkg-status" lockfile
// used by the Debian Package (dpkg) to record installed packages.
func FromDpkgStatus(pathToStatus string) (Lockfile, error) {
	packages, err := ParseDpkgStatus(pathToStatus)

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return Lockfile{
		FilePath: pathToStatus,
		ParsedAs: "dpkg-status",
		Packages: packages,
	}, err
}
