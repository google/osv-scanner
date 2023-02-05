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

func TestParsePipenvLockFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, diag, err := lockfile.ParsePipenvLockFile("fixtures/pipenv/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
	expectDiagnostics(t, diag, lockfile.Diagnostics{})
}

func TestParsePipenvLockFile_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, diag, err := lockfile.ParsePipenvLockFile("fixtures/pipenv/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
	expectDiagnostics(t, diag, lockfile.Diagnostics{})
}

func TestParsePipenvLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParser(t,
		lockfile.ParsePipenvLockFile,
		lockfile.ParsePipenvLockWithDiagnostics,
		[]testParserWithDiagnosticsTest{
			// no packages
			{
				name: "",
				file: "fixtures/pipenv/empty.json",
				want: []lockfile.PackageDetails{},
				diag: lockfile.Diagnostics{},
			},
			// one package
			{
				name: "",
				file: "fixtures/pipenv/one-package.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "markupsafe",
						Version:   "2.1.1",
						Ecosystem: lockfile.PipenvEcosystem,
						CompareAs: lockfile.PipenvEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// one package, dev
			{
				name: "",
				file: "fixtures/pipenv/one-package-dev.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "markupsafe",
						Version:   "2.1.1",
						Ecosystem: lockfile.PipenvEcosystem,
						CompareAs: lockfile.PipenvEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// two packages
			{
				name: "",
				file: "fixtures/pipenv/two-packages.json",
				want: []lockfile.PackageDetails{
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
				},
				diag: lockfile.Diagnostics{},
			},
			// two packages, alt
			{
				name: "",
				file: "fixtures/pipenv/two-packages-alt.json",
				want: []lockfile.PackageDetails{
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
				},
				diag: lockfile.Diagnostics{},
			},
			// multiple packages
		{
			name: "",
			file: "fixtures/pipenv/multiple-packages.json",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{},
		},
		// no version
			{
				name: "",
				file: "fixtures/pipenv/no-version.json",
				want: []lockfile.PackageDetails{},
				diag: lockfile.Diagnostics{},
			},
		})
}
