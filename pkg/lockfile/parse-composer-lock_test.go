package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestComposerLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "composer.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/composer.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/composer.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/composer.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.composer.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.ComposerLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseComposerLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseComposerLock_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseComposerLock("fixtures/composer/not-json.txt")

	expectErrContaining(t, err, "could not extract from")
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
			DepGroups: []string{"dev"},
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
			DepGroups: []string{"dev"},
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
