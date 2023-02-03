package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParsePoetryLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePoetryLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePoetryLock("fixtures/poetry/not-toml.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePoetryLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParsePoetryLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// no packages
		{
			name: "",
			file: "fixtures/poetry/empty.lock",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one package
		{
			name: "",
			file: "fixtures/poetry/one-package.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "numpy",
					Version:   "1.23.3",
					Ecosystem: lockfile.PoetryEcosystem,
					CompareAs: lockfile.PoetryEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages
		{
			name: "",
			file: "fixtures/poetry/two-packages.lock",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{},
		},
		// package with metadata
		{
			name: "",
			file: "fixtures/poetry/one-package-with-metadata.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "emoji",
					Version:   "2.0.0",
					Ecosystem: lockfile.PoetryEcosystem,
					CompareAs: lockfile.PoetryEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// package with git source
		{
			name: "",
			file: "fixtures/poetry/source-git.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "ike",
					Version:   "0.2.0",
					Ecosystem: lockfile.PoetryEcosystem,
					CompareAs: lockfile.PoetryEcosystem,
					Commit:    "cd66602cd29f61a2d2e7fb995fef1e61708c034d",
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// package with legacy source
		{
			name: "",
			file: "fixtures/poetry/source-legacy.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "appdirs",
					Version:   "1.4.4",
					Ecosystem: lockfile.PoetryEcosystem,
					CompareAs: lockfile.PoetryEcosystem,
					Commit:    "",
				},
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
