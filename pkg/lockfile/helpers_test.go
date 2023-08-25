package lockfile_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/lockfile"
)

func expectErrContaining(t *testing.T, err error, str string) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
	}

	if !strings.Contains(err.Error(), str) {
		t.Errorf("Expected to get \"%s\" error, but got \"%v\"", str, err)
	}
}

func packageToString(pkg lockfile.PackageDetails) string {
	commit := pkg.Commit

	if commit == "" {
		commit = "<no commit>"
	}

	return fmt.Sprintf("%s@%s (%s, %s)", pkg.Name, pkg.Version, pkg.Ecosystem, commit)
}

// checks if two strings are equal, treating any occurrences of `%%` in the
// expected string to mean "any text"
func areEqual(t *testing.T, actual, expect string) bool {
	t.Helper()

	expect = regexp.QuoteMeta(expect)
	expect = strings.ReplaceAll(expect, "%%", ".+")

	re := regexp.MustCompile(`^` + expect + `$`)

	return re.MatchString(actual)
}

func hasPackage(t *testing.T, packages []lockfile.PackageDetails, pkg lockfile.PackageDetails) bool {
	t.Helper()
	// Store source here since original source is set to empty string to do equal comparison
	pkgSource := pkg.Source
	for _, details := range packages {
		// Custom source equality check to not be too path specific
		// areEqual is not symmetrical, so compare both ways
		if areEqual(t, pkgSource, details.Source) || areEqual(t, details.Source, pkgSource) {
			details.Source = ""
			pkg.Source = ""
			if details == pkg {
				return true
			}
		}
	}

	return false
}

func expectPackage(t *testing.T, packages []lockfile.PackageDetails, pkg lockfile.PackageDetails) {
	t.Helper()

	if !hasPackage(t, packages, pkg) {
		t.Errorf(
			"Expected packages to include %s@%s (%s, %s), but it did not",
			pkg.Name,
			pkg.Version,
			pkg.Ecosystem,
			pkg.CompareAs,
		)
	}
}

func findMissingPackages(t *testing.T, actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails) []lockfile.PackageDetails {
	t.Helper()
	var missingPackages []lockfile.PackageDetails

	for _, pkg := range actualPackages {
		if !hasPackage(t, expectedPackages, pkg) {
			missingPackages = append(missingPackages, pkg)
		}
	}

	return missingPackages
}

func expectPackages(t *testing.T, actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails) {
	t.Helper()

	if len(expectedPackages) != len(actualPackages) {
		t.Errorf(
			"Expected to get %d %s, but got %d",
			len(expectedPackages),
			output.Form(len(expectedPackages), "package", "packages"),
			len(actualPackages),
		)
	}

	missingActualPackages := findMissingPackages(t, actualPackages, expectedPackages)
	missingExpectedPackages := findMissingPackages(t, expectedPackages, actualPackages)

	if len(missingActualPackages) != 0 {
		for _, unexpectedPackage := range missingActualPackages {
			t.Errorf("Did not expect %s", packageToString(unexpectedPackage))
		}
	}

	if len(missingExpectedPackages) != 0 {
		for _, unexpectedPackage := range missingExpectedPackages {
			t.Errorf("Did not find %s", packageToString(unexpectedPackage))
		}
	}
}
