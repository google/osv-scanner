package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestPoetryLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "poetry.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/poetry.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/poetry.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/poetry.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.poetry.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.PoetryLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePoetryLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePoetryLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/not-toml.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePoetryLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePoetryLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/one-package.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "numpy",
			Version:   "1.23.3",
			Ecosystem: lockfile.PoetryEcosystem,
			CompareAs: lockfile.PoetryEcosystem,
		},
	})
}

func TestParsePoetryLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/two-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "proto-plus",
			Version:   "1.22.0",
			Ecosystem: lockfile.PoetryEcosystem,
			CompareAs: lockfile.PoetryEcosystem,
		},
		{
			Name:      "protobuf",
			Version:   "4.21.5",
			Ecosystem: lockfile.PoetryEcosystem,
			CompareAs: lockfile.PoetryEcosystem,
		},
	})
}

func TestParsePoetryLock_PackageWithMetadata(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/one-package-with-metadata.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "emoji",
			Version:   "2.0.0",
			Ecosystem: lockfile.PoetryEcosystem,
			CompareAs: lockfile.PoetryEcosystem,
		},
	})
}

func TestParsePoetryLock_PackageWithGitSource(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/source-git.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "ike",
			Version:   "0.2.0",
			Ecosystem: lockfile.PoetryEcosystem,
			CompareAs: lockfile.PoetryEcosystem,
			Commit:    "cd66602cd29f61a2d2e7fb995fef1e61708c034d",
		},
	})
}

func TestParsePoetryLock_PackageWithLegacySource(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/source-legacy.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "appdirs",
			Version:   "1.4.4",
			Ecosystem: lockfile.PoetryEcosystem,
			CompareAs: lockfile.PoetryEcosystem,
			Commit:    "",
		},
	})
}

func TestParsePoetryLock_OptionalPackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/optional-package.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "numpy",
			Version:   "1.23.3",
			Ecosystem: lockfile.PoetryEcosystem,
			CompareAs: lockfile.PoetryEcosystem,
			DepGroups: []string{"optional"},
		},
	})
}
