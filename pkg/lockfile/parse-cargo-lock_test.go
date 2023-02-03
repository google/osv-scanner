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

func TestParseCargoLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseCargoLock("fixtures/cargo/not-toml.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseCargoLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseCargoLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// no packages
		{
			name: "",
			file: "fixtures/cargo/empty.lock",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one package
		{
			name: "",
			file: "fixtures/cargo/one-package.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Ecosystem: lockfile.CargoEcosystem,
					CompareAs: lockfile.CargoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages
		{
			name: "",
			file: "fixtures/cargo/two-packages.lock",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{},
		},
		// package with build string
		{
			name: "",
			file: "fixtures/cargo/package-with-build-string.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "wasi",
					Version:   "0.10.2+wasi-snapshot-preview1",
					Ecosystem: lockfile.CargoEcosystem,
					CompareAs: lockfile.CargoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
