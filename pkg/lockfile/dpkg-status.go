package lockfile

import (
	"bufio"
	"fmt"
	"sort"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
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
	re := cachedregexp.MustCompile(`^(.*)\((.*)\)`)
	matches := re.FindStringSubmatch(source)
	if len(matches) == 3 {
		return strings.TrimSpace(matches[1]), strings.TrimSpace(matches[2])
	}
	// If it not matches the pattern "name (version)", it is only "name"
	return strings.TrimSpace(source), ""
}

func parseDpkgPackageGroup(group []string) PackageDetails {
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
			// Status field is malformed. Expected: "Status: Want Flag Status"
			if len(tokens) != 3 {
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

	return pkg
}

// Deprecated: use DpkgStatusExtractor.Extract instead
func ParseDpkgStatus(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, DpkgStatusExtractor{})
}

type DpkgStatusExtractor struct{}

func (e DpkgStatusExtractor) ShouldExtract(path string) bool {
	return path == "/var/lib/dpkg/status"
}

func (e DpkgStatusExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	scanner := bufio.NewScanner(f)
	packageGroups := groupDpkgPackageLines(scanner)

	packages := make([]PackageDetails, 0, len(packageGroups))

	for _, group := range packageGroups {
		pkg := parseDpkgPackageGroup(group)

		// PackageDetails does not contain any field that represent a "not installed" state
		// To manage this state and avoid false positives, empty ecosystem means "not installed" so skip it
		if pkg.Ecosystem == "" {
			continue
		}

		if pkg.Name == "" {
			continue
		}

		packages = append(packages, pkg)
	}

	debianReleaseVersion := getReleaseVersion(packages)
	if debianReleaseVersion != "" {
		for i := range packages {
			packages[i].Ecosystem = Ecosystem(string(packages[i].Ecosystem) + ":" + debianReleaseVersion)
		}
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	return packages, nil
}

func getReleaseVersion(packages []PackageDetails) string {
	for _, pkg := range packages {
		if pkg.Name != "base-files" {
			continue
		}

		// We only care about the major version
		// Example base-files version: 12.4+deb12u5
		versionWithMinor, _, _ := strings.Cut(pkg.Version, "+")
		majorVersion, _, _ := strings.Cut(versionWithMinor, ".")

		return majorVersion
	}

	return ""
}

var _ Extractor = DpkgStatusExtractor{}

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
