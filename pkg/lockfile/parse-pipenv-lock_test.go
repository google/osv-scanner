package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParsePipenvLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePipenvLock_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePipenvLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/empty.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePipenvLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/one-package.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
	})
}

func TestParsePipenvLock_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/one-package-dev.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
	})
}

func TestParsePipenvLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/two-packages.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "itsdangerous",
			Version:   "2.1.2",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
	})
}

func TestParsePipenvLock_TwoPackagesAlt(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/two-packages-alt.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "itsdangerous",
			Version:   "2.1.2",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
	})
}

func TestParsePipenvLock_MultiplePackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/multiple-packages.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "itsdangerous",
			Version:   "2.1.2",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
		{
			Name:      "pluggy",
			Version:   "1.0.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
		{
			Name:      "pluggy",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
		},
	})
}

func TestParsePipenvLock_PackageWithoutVersion(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/no-version.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}
