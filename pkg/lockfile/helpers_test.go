package lockfile_test

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/lockfile"
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

func expectErrIs(t *testing.T, err error, expected error) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
	}

	if !errors.Is(err, expected) {
		t.Errorf("Expected to get \"%v\" error but got \"%v\" instead", expected, err)
	}
}

func packageToString(pkg lockfile.PackageDetails) string {
	commit := pkg.Commit

	if commit == "" {
		commit = "<no commit>"
	}

	groups := strings.Join(pkg.DepGroups, ", ")

	if groups == "" {
		groups = "<no groups>"
	}

	return fmt.Sprintf("%s@%s (%s, %s, %s)", pkg.Name, pkg.Version, pkg.Ecosystem, commit, groups)
}

func hasPackage(t *testing.T, packages []lockfile.PackageDetails, pkg lockfile.PackageDetails) bool {
	t.Helper()

	for _, details := range packages {
		if reflect.DeepEqual(details, pkg) {
			return true
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

func createTestDir(t *testing.T) (string, func()) {
	t.Helper()

	p, err := os.MkdirTemp("", "osv-scanner-test-*")
	if err != nil {
		t.Fatalf("could not create test directory: %v", err)
	}

	return p, func() {
		_ = os.RemoveAll(p)
	}
}

func copyFile(t *testing.T, from, to string) string {
	t.Helper()

	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("could not read test file: %v", err)
	}

	if err := os.WriteFile(to, b, 0600); err != nil {
		t.Fatalf("could not copy test file: %v", err)
	}

	return to
}
