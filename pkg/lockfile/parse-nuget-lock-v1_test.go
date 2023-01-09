package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseNuGetLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLock_v1_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLock_v1_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/empty.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLock_v1_OneFramework_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/one-framework-one-package.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "Test.Core",
			Version:   "6.0.5",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
	})
}

func TestParseNuGetLock_v1_OneFramework_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/one-framework-two-packages.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "Test.Core",
			Version:   "6.0.5",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
		{
			Name:      "Test.System",
			Version:   "0.13.0-beta4",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
	})
}

func TestParseNuGetLock_v1_TwoFrameworks_MixedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/two-frameworks-mixed-packages.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "Test.Core",
			Version:   "6.0.5",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
		{
			Name:      "Test.System",
			Version:   "0.13.0-beta4",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
		{
			Name:      "Test.System",
			Version:   "2.15.0",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
	})
}

func TestParseNuGetLock_v1_TwoFrameworks_DifferentPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/two-frameworks-different-packages.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "Test.Core",
			Version:   "6.0.5",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
		{
			Name:      "Test.System",
			Version:   "0.13.0-beta4",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
	})
}

func TestParseNuGetLock_v1_TwoFrameworks_DuplicatePackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/two-frameworks-duplicate-packages.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "Test.Core",
			Version:   "6.0.5",
			Ecosystem: lockfile.NuGetEcosystem,
			CompareAs: lockfile.NuGetEcosystem,
		},
	})
}
