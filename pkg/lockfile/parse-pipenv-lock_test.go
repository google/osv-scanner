package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestPipenvLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "Pipfile.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Pipfile.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Pipfile.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/Pipfile.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.Pipfile.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.PipenvLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePipenvLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePipenvLock_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/not-json.txt")

	expectErrContaining(t, err, "could not decode json from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePipenvLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/empty.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePipenvLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/one-package.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 19, End: 64},
			Column:    models.Position{Start: 9, End: 10},
		},
	})
}

func TestParsePipenvLock_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/one-package-dev.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 20, End: 65},
			Column:    models.Position{Start: 9, End: 10},
			DepGroups: []string{"dev"},
		},
	})
}

func TestParsePipenvLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/two-packages.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "itsdangerous",
			Version:   "2.1.2",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 19, End: 26},
			Column:    models.Position{Start: 7, End: 8},
		},
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 29, End: 74},
			Column:    models.Position{Start: 7, End: 8},
			DepGroups: []string{"dev"},
		},
	})
}

func TestParsePipenvLock_TwoPackagesAlt(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/two-packages-alt.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "itsdangerous",
			Version:   "2.1.2",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 19, End: 26},
			Column:    models.Position{Start: 7, End: 8},
		},
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 27, End: 72},
			Column:    models.Position{Start: 7, End: 8},
		},
	})
}

func TestParsePipenvLock_MultiplePackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/multiple-packages.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "itsdangerous",
			Version:   "2.1.2",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 19, End: 26},
			Column:    models.Position{Start: 7, End: 8},
		},
		{
			Name:      "pluggy",
			Version:   "1.0.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 27, End: 31},
			Column:    models.Position{Start: 7, End: 8},
		},
		{
			Name:      "pluggy",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 88, End: 95},
			Column:    models.Position{Start: 7, End: 8},
			DepGroups: []string{"dev"},
		},
		{
			Name:      "markupsafe",
			Version:   "2.1.1",
			Ecosystem: lockfile.PipenvEcosystem,
			CompareAs: lockfile.PipenvEcosystem,
			Line:      models.Position{Start: 32, End: 77},
			Column:    models.Position{Start: 7, End: 8},
		},
	})
}

func TestParsePipenvLock_PackageWithoutVersion(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePipenvLock("fixtures/pipenv/no-version.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}
