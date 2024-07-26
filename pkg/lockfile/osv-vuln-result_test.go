package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseOSVScannerResults_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
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
		},
	})
}

func TestParseOSVScannerResults_OnePackageCommit(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/one-package-commit.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Commit: "9a6bd55c9d0722cb101fe85a3b22d89e4ff4fe52",
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
		},
		{
			Name:      "memoffset",
			Version:   "0.5.6",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
		},
		{
			Name:      "smallvec",
			Version:   "1.6.0",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
		},
	})
}
