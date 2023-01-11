package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseConanLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v2_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v2_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/empty.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v2_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/one-package.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "zlib",
			Version:   "1.2.11",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
	})
}

func TestParseConanLock_v2_NoName(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/no-name.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "zlib",
			Version:   "1.2.11",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
	})
}

func TestParseConanLock_v2_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/two-packages.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "zlib",
			Version:   "1.2.11",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
		{
			Name:      "bzip2",
			Version:   "1.0.8",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
	})
}

func TestParseConanLock_v2_NestedDependencies(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/nested-dependencies.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "zlib",
			Version:   "1.2.13",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
		{
			Name:      "bzip2",
			Version:   "1.0.8",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
		{
			Name:      "freetype",
			Version:   "2.12.1",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
		{
			Name:      "libpng",
			Version:   "1.6.39",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
		{
			Name:      "brotli",
			Version:   "1.0.9",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
	})
}

func TestParseConanLock_v2_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/one-package-dev.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "ninja",
			Version:   "1.11.1",
			Ecosystem: lockfile.ConanEcosystem,
			CompareAs: lockfile.ConanEcosystem,
		},
	})
}
