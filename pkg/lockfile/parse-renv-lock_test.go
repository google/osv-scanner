package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseRenvLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRenvLock("fixtures/renv/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRenvLock_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRenvLock("fixtures/renv/not-json.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRenvLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRenvLock("fixtures/renv/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRenvLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRenvLock("fixtures/renv/one-package.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "morning",
			Version:   "0.1.0",
			Ecosystem: lockfile.CRANEcosystem,
			CompareAs: lockfile.CRANEcosystem,
		},
	})
}

func TestParseRenvLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRenvLock("fixtures/renv/two-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "markdown",
			Version:   "1.0",
			Ecosystem: lockfile.CRANEcosystem,
			CompareAs: lockfile.CRANEcosystem,
		},
		{
			Name:      "mime",
			Version:   "0.7",
			Ecosystem: lockfile.CRANEcosystem,
			CompareAs: lockfile.CRANEcosystem,
		},
	})
}

func TestParseRenvLock_WithMixedSources(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRenvLock("fixtures/renv/with-mixed-sources.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "markdown",
			Version:   "1.0",
			Ecosystem: lockfile.CRANEcosystem,
			CompareAs: lockfile.CRANEcosystem,
		},
	})
}

func TestParseRenvLock_WithBioconductor(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRenvLock("fixtures/renv/with-bioconductor.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// currently Bioconductor is not supported
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "BH",
			Version:   "1.75.0-0",
			Ecosystem: lockfile.CRANEcosystem,
			CompareAs: lockfile.CRANEcosystem,
		},
	})
}

func TestParseRenvLock_WithoutRepository(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRenvLock("fixtures/renv/without-repository.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}
