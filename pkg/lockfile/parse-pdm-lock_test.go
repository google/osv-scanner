package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestPdmExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty",
			path: "",
			want: false,
		},
		{
			name: "plain",
			path: "pdm.lock",
			want: true,
		},
		{
			name: "absolute",
			path: "/path/to/pdm.lock",
			want: true,
		},
		{
			name: "relative",
			path: "../../pdm.lock",
			want: true,
		},
		{
			name: "in-path",
			path: "/path/with/pdm.lock/in/middle",
			want: false,
		},
		{
			name: "invalid-suffix",
			path: "pdm.lock.file",
			want: false,
		},
		{
			name: "invalid-prefix",
			path: "project.name.pdm.lock",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ext := lockfile.PdmLockExtractor{}
			should := ext.ShouldExtract(tt.path)
			if should != tt.want {
				t.Errorf("ShouldExtract() - got %v, expected %v", should, tt.want)
			}
		})
	}
}

func expectNilErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}
}

func TestParsePdmLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePdmLock("fixtures/pdm/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePdmLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePdmLock("fixtures/pdm/not-toml.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePdmLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePdmLock("fixtures/pdm/empty.toml")

	expectNilErr(t, err)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePdmLock_SinglePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePdmLock("fixtures/pdm/single-package.toml")

	expectNilErr(t, err)
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "toml",
			Version:   "0.10.2",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
		},
	})
}

func TestParsePdmLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePdmLock("fixtures/pdm/two-packages.toml")

	expectNilErr(t, err)
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "toml",
			Version:   "0.10.2",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
		},
		{
			Name:      "six",
			Version:   "1.16.0",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
		},
	})
}

func TestParsePdmLock_PackageWithDevDependencies(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePdmLock("fixtures/pdm/dev-dependency.toml")

	expectNilErr(t, err)
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "toml",
			Version:   "0.10.2",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
		},
		{
			Name:      "pyroute2",
			Version:   "0.7.11",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
			DepGroups: []string{"dev"},
		},
		{
			Name:      "win-inet-pton",
			Version:   "1.1.0",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
			DepGroups: []string{"dev"},
		},
	})
}

func TestParsePdmLock_PackageWithOptionalDependency(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePdmLock("fixtures/pdm/optional-dependency.toml")

	expectNilErr(t, err)
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "toml",
			Version:   "0.10.2",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
		},
		{
			Name:      "pyroute2",
			Version:   "0.7.11",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
			DepGroups: []string{"optional"},
		},
		{
			Name:      "win-inet-pton",
			Version:   "1.1.0",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
			DepGroups: []string{"optional"},
		},
	})
}

func TestParsePdmLock_PackageWithGitDependency(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePdmLock("fixtures/pdm/git-dependency.toml")

	expectNilErr(t, err)
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "toml",
			Version:   "0.10.2",
			Ecosystem: lockfile.PdmEcosystem,
			CompareAs: lockfile.PdmEcosystem,
			Commit:    "65bab7582ce14c55cdeec2244c65ea23039c9e6f",
		},
	})
}
