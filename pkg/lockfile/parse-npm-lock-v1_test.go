package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseNpmLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v1_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/not-json.txt")

	expectErrContaining(t, err, "could not decode json from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v1_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/empty.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v1_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/one-package.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 5, End: 9},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v1_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/one-package-dev.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 5, End: 10},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			DepGroups: []string{"dev"},
		},
	})
}

func TestParseNpmLock_v1_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/two-packages.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 5, End: 9},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Line:      models.Position{Start: 10, End: 17},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v1_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/scoped-packages.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 13, End: 17},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "@babel/code-frame",
			Version:   "7.0.0",
			Line:      models.Position{Start: 5, End: 12},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v1_NestedDependencies(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/nested-dependencies.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "postcss",
			Version:   "6.0.23",
			Line:      models.Position{Start: 5, End: 14},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "postcss",
			Version:   "7.0.16",
			Line:      models.Position{Start: 26, End: 35},
			Column:    models.Position{Start: 9, End: 10},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "postcss-calc",
			Version:   "7.0.1",
			Line:      models.Position{Start: 15, End: 45},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "6.1.0",
			Line:      models.Position{Start: 36, End: 43},
			Column:    models.Position{Start: 9, End: 10},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Line:      models.Position{Start: 46, End: 53},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v1_NestedDependenciesDup(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/nested-dependencies-dup.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// todo: convert to using expectPackages w/ listing all expected packages
	if len(packages) != 39 {
		t.Errorf("Expected to get 39 packages, but got %d", len(packages))
	}

	expectPackage(t, packages, lockfile.PackageDetails{
		Name:      "supports-color",
		Version:   "6.1.0",
		Line:      models.Position{Start: 21, End: 28},
		Column:    models.Position{Start: 9, End: 10},
		Ecosystem: lockfile.NpmEcosystem,
		CompareAs: lockfile.NpmEcosystem,
	})

	expectPackage(t, packages, lockfile.PackageDetails{
		Name:      "supports-color",
		Version:   "5.5.0",
		Line:      models.Position{Start: 759, End: 766},
		Column:    models.Position{Start: 5, End: 6},
		Ecosystem: lockfile.NpmEcosystem,
		CompareAs: lockfile.NpmEcosystem,
	})

	expectPackage(t, packages, lockfile.PackageDetails{
		Name:      "supports-color",
		Version:   "2.0.0",
		Line:      models.Position{Start: 64, End: 68},
		Column:    models.Position{Start: 9, End: 10},
		Ecosystem: lockfile.NpmEcosystem,
		CompareAs: lockfile.NpmEcosystem,
	})
}

func TestParseNpmLock_v1_Commits(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/commits.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@segment/analytics.js-integration-facebook-pixel",
			Version:   "",
			Line:      models.Position{Start: 5, End: 18},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
		},
		{
			Name:      "ansi-styles",
			Version:   "1.0.0",
			Line:      models.Position{Start: 19, End: 23},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "babel-preset-php",
			Version:   "",
			Line:      models.Position{Start: 24, End: 30},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
		},
		{
			Name:      "is-number-1",
			Version:   "",
			Line:      models.Position{Start: 31, End: 37},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-1",
			Version:   "",
			Line:      models.Position{Start: 75, End: 81},
			Column:    models.Position{Start: 9, End: 10},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "be5935f8d2595bcd97b05718ef1eeae08d812e10",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-2",
			Version:   "",
			Line:      models.Position{Start: 38, End: 41},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
		},
		{
			Name:      "is-number-2",
			Version:   "",
			Line:      models.Position{Start: 82, End: 85},
			Column:    models.Position{Start: 9, End: 10},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "82dcc8e914dabd9305ab9ae580709a7825e824f5",
		},
		{
			Name:      "is-number-3",
			Version:   "",
			Line:      models.Position{Start: 42, End: 46},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-3",
			Version:   "",
			Line:      models.Position{Start: 86, End: 90},
			Column:    models.Position{Start: 9, End: 10},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-4",
			Version:   "",
			Line:      models.Position{Start: 47, End: 54},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-5",
			Version:   "",
			Line:      models.Position{Start: 55, End: 62},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-6",
			Version:   "",
			Line:      models.Position{Start: 63, End: 69},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "postcss-calc",
			Version:   "7.0.1",
			Line:      models.Position{Start: 70, End: 92},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "raven-js",
			Version:   "",
			Line:      models.Position{Start: 93, End: 96},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
		},
		{
			Name:      "slick-carousel",
			Version:   "",
			Line:      models.Position{Start: 97, End: 101},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "280b560161b751ba226d50c7db1e0a14a78c2de0",
			DepGroups: []string{"dev"},
		},
	})
}

func TestParseNpmLock_v1_Files(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/files.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "lodash",
			Version:   "1.3.1",
			Line:      models.Position{Start: 5, End: 9},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "other_package",
			Version:   "0.0.0",
			Line:      models.Position{Start: 10, End: 15},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
	})
}

func TestParseNpmLock_v1_Alias(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/alias.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@babel/code-frame",
			Version:   "7.0.0",
			Line:      models.Position{Start: 5, End: 12},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "string-width",
			Version:   "4.2.0",
			Line:      models.Position{Start: 23, End: 32},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "string-width",
			Version:   "5.1.2",
			Line:      models.Position{Start: 13, End: 22},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v1_OptionalPackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/optional-package.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 5, End: 11},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			DepGroups: []string{"dev", "optional"},
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Line:      models.Position{Start: 12, End: 20},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			DepGroups: []string{"optional"},
		},
	})
}
