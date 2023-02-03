package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseYarnLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/does-not-exist")

	expectErrContaining(t, err, "could not open")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLockWithDiagnostics_v2(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseYarnLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// no packages
		{
			name: "",
			file: "fixtures/yarn/empty.v2.lock",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one package
		{
			name: "",
			file: "fixtures/yarn/one-package.v2.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "balanced-match",
					Version:   "1.0.2",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages
		{
			name: "",
			file: "fixtures/yarn/two-packages.v2.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "compare-func",
					Version:   "2.0.0",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
				{
					Name:      "concat-map",
					Version:   "0.0.1",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages (with quotes)
		{
			name: "",
			file: "fixtures/yarn/with-quotes.v2.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "compare-func",
					Version:   "2.0.0",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
				{
					Name:      "concat-map",
					Version:   "0.0.1",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// multiple versions
		{
			name: "",
			file: "fixtures/yarn/multiple-versions.v2.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "debug",
					Version:   "4.3.3",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
				{
					Name:      "debug",
					Version:   "2.6.9",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
				{
					Name:      "debug",
					Version:   "3.2.7",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// scoped packages
		{
			name: "",
			file: "fixtures/yarn/scoped-packages.v2.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "@babel/cli",
					Version:   "7.16.8",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
				{
					Name:      "@babel/code-frame",
					Version:   "7.16.7",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
				{
					Name:      "@babel/compat-data",
					Version:   "7.16.8",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// versions with build strings
		{
			name: "",
			file: "fixtures/yarn/versions-with-build-strings.v2.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "@nicolo-ribaudo/chokidar-2",
					Version:   "2.1.8-no-fsevents.3",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
				{
					Name:      "gensync",
					Version:   "1.0.0-beta.2",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
				{
					Name:      "eslint-plugin-jest",
					Version:   "0.0.0-use.local",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// commits
		{
			name: "",
			file: "fixtures/yarn/commits.v2.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "@my-scope/my-first-package",
					Version:   "0.0.6",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
					Commit:    "0b824c650d3a03444dbcf2b27a5f3566f6e41358",
				},
				{
					Name:      "my-second-package",
					Version:   "0.2.2",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
					Commit:    "59e2127b9f9d4fda5f928c4204213b3502cd5bb0",
				},
				{
					Name:      "@typegoose/typegoose",
					Version:   "7.2.0",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
					Commit:    "3ed06e5097ab929f69755676fee419318aaec73a",
				},
				{
					Name:      "vuejs",
					Version:   "2.5.0",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
					Commit:    "0948d999f2fddf9f90991956493f976273c5da1f",
				},
				{
					Name:      "my-third-package",
					Version:   "0.16.1-dev",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
					Commit:    "5675a0aed98e067ff6ecccc5ac674fe8995960e0",
				},
				{
					Name:      "my-node-sdk",
					Version:   "1.1.0",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
					Commit:    "053dea9e0b8af442d8f867c8e690d2fb0ceb1bf5",
				},
				{
					Name:      "is-really-great",
					Version:   "1.0.0",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
					Commit:    "191eeef50c584714e1fb8927d17ee72b3b8c97c4",
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// files
		{
			name: "",
			file: "fixtures/yarn/files.v2.lock",
			want: []lockfile.PackageDetails{
				{
					Name:      "my-package",
					Version:   "0.0.2",
					Ecosystem: lockfile.YarnEcosystem,
					CompareAs: lockfile.YarnEcosystem,
					Commit:    "",
				},
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
