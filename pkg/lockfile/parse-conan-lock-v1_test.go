package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseConanLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v1_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseConanLock("fixtures/conan/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLockFile_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, diag, err := lockfile.ParseConanLockFile("fixtures/conan/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
	expectDiagnostics(t, diag, lockfile.Diagnostics{})
}

func TestParseConanLockFile_v1_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, diag, err := lockfile.ParseConanLockFile("fixtures/conan/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
	expectDiagnostics(t, diag, lockfile.Diagnostics{})
}

func TestParseConanLockWithDiagnostics_1(t *testing.T) {
	t.Parallel()

	testParser(t,
		lockfile.ParseConanLockFile,
		lockfile.ParseConanLockWithDiagnostics,
		[]testParserWithDiagnosticsTest{
			// no packages
			{
				name: "",
				file: "fixtures/conan/empty.v1.json",
				want: []lockfile.PackageDetails{},
				diag: lockfile.Diagnostics{},
			},
			// one package
			{
				name: "",
				file: "fixtures/conan/one-package.v1.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "zlib",
						Version:   "1.2.11",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// one package, dev
			{
				name: "",
				file: "fixtures/conan/one-package-dev.v1.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "ninja",
						Version:   "1.11.1",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// two packages
			{
				name: "",
				file: "fixtures/conan/two-packages.v1.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "zlib",
						Version:   "1.2.11",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
					{
						Name:      "bzip2",
						Version:   "1.0.8",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// no name
			{
				name: "",
				file: "fixtures/conan/no-name.v1.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "zlib",
						Version:   "1.2.11",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// nested dependencies
			{
				name: "",
				file: "fixtures/conan/nested-dependencies.v1.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "zlib",
						Version:   "1.2.13",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
					{
						Name:      "bzip2",
						Version:   "1.0.8",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
					{
						Name:      "freetype",
						Version:   "2.12.1",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
					{
						Name:      "libpng",
						Version:   "1.6.39",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
					{
						Name:      "brotli",
						Version:   "1.0.9",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// old format (0.0)
			{
				name: "",
				file: "fixtures/conan/old-format-0.0.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "zlib",
						Version:   "1.2.11",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// old format (0.1)
			{
				name: "",
				file: "fixtures/conan/old-format-0.1.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "zlib",
						Version:   "1.2.11",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// old format (0.2)
			{
				name: "",
				file: "fixtures/conan/old-format-0.2.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "zlib",
						Version:   "1.2.11",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
			// old format (0.3)
			{
				name: "",
				file: "fixtures/conan/old-format-0.3.json",
				want: []lockfile.PackageDetails{
					{
						Name:      "zlib",
						Version:   "1.2.11",
						Ecosystem: lockfile.ConanEcosystem,
						CompareAs: lockfile.ConanEcosystem,
					},
				},
				diag: lockfile.Diagnostics{},
			},
		})
}
