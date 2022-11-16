package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseCargoLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseCargoLock_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/not-toml.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseCargoLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseCargoLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/one-package.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "addr2line",
			Version:   "0.15.2",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
		},
	})
}

func TestParseCargoLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/two-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "addr2line",
			Version:   "0.15.2",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
		},
		{
			Name:      "syn",
			Version:   "1.0.73",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
		},
	})
}

func TestParseCargoLock_PackageWithBuildString(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/package-with-build-string.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wasi",
			Version:   "0.10.2+wasi-snapshot-preview1",
			Ecosystem: lockfile.CargoEcosystem,
			CompareAs: lockfile.CargoEcosystem,
		},
	})
}
