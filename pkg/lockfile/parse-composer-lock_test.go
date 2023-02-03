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

func TestParseComposerLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseComposerLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// no packages
		{
			name: "",
			file: "fixtures/composer/empty.json",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one package
		{
			name: "",
			file: "fixtures/composer/one-package.json",
			want: []lockfile.PackageDetails{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Commit:    "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					Ecosystem: lockfile.ComposerEcosystem,
					CompareAs: lockfile.ComposerEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// one package, dev
		{
			name: "",
			file: "fixtures/composer/one-package-dev.json",
			want: []lockfile.PackageDetails{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Commit:    "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					Ecosystem: lockfile.ComposerEcosystem,
					CompareAs: lockfile.ComposerEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages
		{
			name: "",
			file: "fixtures/composer/two-packages.json",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages, alt
		{
			name: "",
			file: "fixtures/composer/two-packages-alt.json",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
