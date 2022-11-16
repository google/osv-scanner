package lockfile_test

import (
	"fmt"
	"github.com/google/osv-scanner/pkg/lockfile"
	"strings"
	"testing"
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

func hasPackage(packages []lockfile.PackageDetails, pkg lockfile.PackageDetails) bool {
	for _, details := range packages {
		if details == pkg {
			return true
		}
	}

	return false
}

func expectPackage(t *testing.T, packages []lockfile.PackageDetails, pkg lockfile.PackageDetails) {
	t.Helper()

	if !hasPackage(packages, pkg) {
		t.Errorf(
			"Expected packages to include %s@%s (%s, %s), but it did not",
			pkg.Name,
			pkg.Version,
			pkg.Ecosystem,
			pkg.CompareAs,
		)
	}
}

func findMissingPackages(actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails) []lockfile.PackageDetails {
	var missingPackages []lockfile.PackageDetails

	for _, pkg := range actualPackages {
		if !hasPackage(expectedPackages, pkg) {
			missingPackages = append(missingPackages, pkg)
		}
	}

	return missingPackages
}

func expectPackages(t *testing.T, actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails) {
	t.Helper()

	if len(expectedPackages) != len(actualPackages) {
		t.Errorf("Expected to get %d packages, but got %d", len(expectedPackages), len(actualPackages))
	}

	missingActualPackages := findMissingPackages(actualPackages, expectedPackages)
	missingExpectedPackages := findMissingPackages(expectedPackages, actualPackages)

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
