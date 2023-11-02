package exclusions

import (
	"fmt"
	"regexp"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/sbom"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
)

// ExcludePackages checks for matches in a Lockfile's Packages against the list of provided exclusion regex patterns.
// If a match is found, the package is removed from the Lockfile's Packages.
// The updated Lockfile is returned.
func ExcludePackages(r reporter.Reporter, exclusionRegexes []*regexp.Regexp, parsedLockfile *lockfile.Lockfile) (*lockfile.Lockfile, error) {
	filteredPackages := make([]lockfile.PackageDetails, 0)

	for _, pkg := range parsedLockfile.Packages {
		matched := checkForRegexMatch(r, exclusionRegexes, pkg.Name)
		if matched {
			continue
		}
		filteredPackages = append(filteredPackages, pkg)
	}
	parsedLockfile.Packages = filteredPackages

	return parsedLockfile, nil
}

// ExcludeSBOMPackages checks if SBOM's ID matches the list of provided exclusion regex patterns.
// If a match is found, the SBOM PURL is excluded from the OSV query by returning a boolean value of true to the calling scanSBOMFile function.
func ExcludeSBOMPackages(r reporter.Reporter, exclusionRegexes []*regexp.Regexp, id *sbom.Identifier) (bool, error) {
	matched := checkForRegexMatch(r, exclusionRegexes, id.PURL)
	if matched {
		return true, nil
	}

	return false, nil
}

// IsRegexPatterns checks if a list of regex patterns are valid regex patterns.
func IsRegexPatterns(patterns []string) error {
	for _, pattern := range patterns {
		if !isValidRegex(pattern) {
			return fmt.Errorf("%s", pattern)
		}
	}

	return nil
}

// ParseExclusions parses a list of regex patterns into a list of regex objects.
func ParseExclusions(patterns []string) ([]*regexp.Regexp, error) {
	exclusionRegexes := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		re, err := cachedregexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid exclusion pattern: %w", err)
		}
		exclusionRegexes[i] = re
	}

	return exclusionRegexes, nil
}

func checkForRegexMatch(r reporter.Reporter, exclusionRegexes []*regexp.Regexp, pkg string) bool {
	for _, re := range exclusionRegexes {
		matched := false
		if re.MatchString(pkg) {
			r.PrintText(fmt.Sprintf("Regex Match Found for exclusion pattern: '%s'\n", re.String()))
			r.PrintText(fmt.Sprintf("Excluding package from OSV query: %s\n", pkg))
			matched = true
		}
		if matched {
			return true
		}
	}

	return false
}

func isValidRegex(pattern string) bool {
	_, err := cachedregexp.Compile(pattern)
	return err == nil
}
