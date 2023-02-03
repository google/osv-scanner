package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseNuGetLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLock_v1_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseNuGetLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// no packages
		{
			name: "",
			file: "fixtures/nuget/empty.v1.json",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one framework, one package
		{
			name: "",
			file: "fixtures/nuget/one-framework-one-package.v1.json",
			want: []lockfile.PackageDetails{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// one framework, two packages
		{
			name: "",
			file: "fixtures/nuget/one-framework-two-packages.v1.json",
			want: []lockfile.PackageDetails{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two frameworks, mixed packages
		{
			name: "",
			file: "fixtures/nuget/two-frameworks-mixed-packages.v1.json",
			want: []lockfile.PackageDetails{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
				{
					Name:      "Test.System",
					Version:   "2.15.0",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two frameworks, different packages
		{
			name: "",
			file: "fixtures/nuget/two-frameworks-different-packages.v1.json",
			want: []lockfile.PackageDetails{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two frameworks, duplicate packages
		{
			name: "",
			file: "fixtures/nuget/two-frameworks-duplicate-packages.v1.json",
			want: []lockfile.PackageDetails{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Ecosystem: lockfile.NuGetEcosystem,
					CompareAs: lockfile.NuGetEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
