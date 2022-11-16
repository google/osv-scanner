package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseComposerLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseComposerLock_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseComposerLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/empty.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseComposerLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/one-package.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "sentry/sdk",
			Version:   "2.0.4",
			Commit:    "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
			Ecosystem: lockfile.ComposerEcosystem,
			CompareAs: lockfile.ComposerEcosystem,
		},
	})
}

func TestParseComposerLock_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/one-package-dev.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "sentry/sdk",
			Version:   "2.0.4",
			Commit:    "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
			Ecosystem: lockfile.ComposerEcosystem,
			CompareAs: lockfile.ComposerEcosystem,
		},
	})
}

func TestParseComposerLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/two-packages.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "sentry/sdk",
			Version:   "2.0.4",
			Commit:    "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
			Ecosystem: lockfile.ComposerEcosystem,
			CompareAs: lockfile.ComposerEcosystem,
		},
		{
			Name:      "theseer/tokenizer",
			Version:   "1.1.3",
			Commit:    "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
			Ecosystem: lockfile.ComposerEcosystem,
			CompareAs: lockfile.ComposerEcosystem,
		},
	})
}

func TestParseComposerLock_TwoPackagesAlt(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/two-packages-alt.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "sentry/sdk",
			Version:   "2.0.4",
			Commit:    "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
			Ecosystem: lockfile.ComposerEcosystem,
			CompareAs: lockfile.ComposerEcosystem,
		},
		{
			Name:      "theseer/tokenizer",
			Version:   "1.1.3",
			Commit:    "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
			Ecosystem: lockfile.ComposerEcosystem,
			CompareAs: lockfile.ComposerEcosystem,
		},
	})
}
