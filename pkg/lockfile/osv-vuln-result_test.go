package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseOSVScannerResults_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/does-not-exist")

	expectErrContaining(t, err, "no such file or directory")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseOSVScannerResults_InvalidJSON(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/not-json.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseOSVScannerResults_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/empty.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseOSVScannerResults_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/one-package.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "activesupport",
			Version:   "7.0.7",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
			Source:    "/path/to/Gemfile.lock",
		},
	})
}

func TestParseOSVScannerResults_MultiPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/multi-packages-with-vulns.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "crossbeam-utils",
			Version:   "0.6.6",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
			Source:    "/path/to/Cargo.lock",
		},
		{
			Name:      "memoffset",
			Version:   "0.5.6",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
			Source:    "/path/to/Cargo.lock",
		},
		{
			Name:      "smallvec",
			Version:   "1.6.0",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
			Source:    "/path/to/Cargo.lock",
		},
	})
}
