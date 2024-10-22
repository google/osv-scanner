package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestCargoLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "Cargo.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Cargo.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Cargo.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/Cargo.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.Cargo.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.CargoLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCargoLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseCargoLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/not-toml.txt")

	expectErrContaining(t, err, "could not extract from")
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

func TestParseCargoLock_TwoPackagesWithLocal(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/two-packages-with-local.lock")

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
			Name:      "local-rust-pkg",
			Version:   "0.1.0",
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
