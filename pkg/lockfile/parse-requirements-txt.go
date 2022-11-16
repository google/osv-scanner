package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const PipEcosystem Ecosystem = "PyPI"

// todo: expand this to support more things, e.g.
//   https://pip.pypa.io/en/stable/reference/requirements-file-format/#example
func parseLine(line string) PackageDetails {
	var constraint string
	name := line

	version := "0.0.0"

	if strings.Contains(line, "==") {
		constraint = "=="
	}

	if strings.Contains(line, ">=") {
		constraint = ">="
	}

	if strings.Contains(line, "~=") {
		constraint = "~="
	}

	if strings.Contains(line, "!=") {
		constraint = "!="
	}

	if constraint != "" {
		splitted := strings.Split(line, constraint)

		name = strings.TrimSpace(splitted[0])

		if constraint != "!=" {
			version = strings.TrimSpace(splitted[1])
		}
	}

	return PackageDetails{
		Name:      normalizedRequirementName(name),
		Version:   version,
		Ecosystem: PipEcosystem,
		CompareAs: PipEcosystem,
	}
}

// normalizedName ensures that the package name is normalized per PEP-0503
// and then removing "added support" syntax if present.
//
// This is done to ensure we don't miss any advisories, as while the OSV
// specification says that the normalized name should be used for advisories,
// that's not the case currently in our databases, _and_ Pip itself supports
// non-normalized names in the requirements.txt, so we need to normalize
// on both sides to ensure we don't have false negatives.
//
// It's possible that this will cause some false positives, but that is better
// than false negatives, and can be dealt with when/if it actually happens.
func normalizedRequirementName(name string) string {
	// per https://www.python.org/dev/peps/pep-0503/#normalized-names
	name = regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-")
	name = strings.ToLower(name)
	name = strings.Split(name, "[")[0]

	return name
}

func removeComments(line string) string {
	var re = regexp.MustCompile(`(^|\s+)#.*$`)

	return strings.TrimSpace(re.ReplaceAllString(line, ""))
}

func isNotRequirementLine(line string) bool {
	return line == "" ||
		// flags are not supported
		strings.HasPrefix(line, "-") ||
		// file urls
		strings.HasPrefix(line, "https://") ||
		strings.HasPrefix(line, "http://") ||
		// file paths are not supported (relative or absolute)
		strings.HasPrefix(line, ".") ||
		strings.HasPrefix(line, "/")
}

func ParseRequirementsTxt(pathToLockfile string) ([]PackageDetails, error) {
	var packages []PackageDetails

	file, err := os.Open(pathToLockfile)
	if err != nil {
		return packages, fmt.Errorf("could not open %s: %w", pathToLockfile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := removeComments(scanner.Text())

		if isNotRequirementLine(line) {
			continue
		}

		packages = append(packages, parseLine(line))
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning %s: %w", pathToLockfile, err)
	}

	return packages, nil
}
