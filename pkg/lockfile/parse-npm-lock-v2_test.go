package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseNpmLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/not-json.txt")

	expectErrContaining(t, err, "could not decode json from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/empty.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/one-package.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 10, End: 14},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/one-package-dev.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 10, End: 15},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			DepGroups: []string{"dev"},
		},
	})
}

func TestParseNpmLock_v2_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/two-packages.v2.json")

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
			Name:      "supports-color",
			Version:   "5.5.0",
			Line:      models.Position{Start: 18, End: 28},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/scoped-packages.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 18, End: 22},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "@babel/code-frame",
			Version:   "7.0.0",
			Line:      models.Position{Start: 10, End: 17},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_NestedDependencies(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/nested-dependencies.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "postcss",
			Version:   "6.0.23",
			Line:      models.Position{Start: 10, End: 22},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "postcss",
			Version:   "7.0.16",
			Line:      models.Position{Start: 34, End: 46},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "postcss-calc",
			Version:   "7.0.1",
			Line:      models.Position{Start: 23, End: 33},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "6.1.0",
			Line:      models.Position{Start: 47, End: 57},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Line:      models.Position{Start: 58, End: 68},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_NestedDependenciesDup(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/nested-dependencies-dup.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "supports-color",
			Version:   "6.1.0",
			Line:      models.Position{Start: 10, End: 20},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "2.0.0",
			Line:      models.Position{Start: 32, End: 39},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_Commits(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/commits.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@segment/analytics.js-integration-facebook-pixel",
			Version:   "2.4.1",
			Line:      models.Position{Start: 26, End: 41},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
		},
		{
			Name:      "ansi-styles",
			Version:   "1.0.0",
			Line:      models.Position{Start: 42, End: 49},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "babel-preset-php",
			Version:   "1.1.1",
			Line:      models.Position{Start: 50, End: 59},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-1",
			Version:   "3.0.0",
			Line:      models.Position{Start: 60, End: 72},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-1",
			Version:   "3.0.0",
			Line:      models.Position{Start: 130, End: 142},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "be5935f8d2595bcd97b05718ef1eeae08d812e10",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-2",
			Version:   "2.0.0",
			Line:      models.Position{Start: 73, End: 82},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-2",
			Version:   "2.0.0",
			Line:      models.Position{Start: 143, End: 152},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "82dcc8e914dabd9305ab9ae580709a7825e824f5",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-3",
			Version:   "2.0.0",
			Line:      models.Position{Start: 83, End: 92},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-3",
			Version:   "3.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Line:      models.Position{Start: 153, End: 162},
			Column:    models.Position{Start: 5, End: 6},
			Commit:    "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-4",
			Version:   "3.0.0",
			Line:      models.Position{Start: 93, End: 105},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-5",
			Version:   "3.0.0",
			Line:      models.Position{Start: 106, End: 118},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "postcss-calc",
			Version:   "7.0.1",
			Line:      models.Position{Start: 119, End: 129},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "raven-js",
			Version:   "",
			Line:      models.Position{Start: 163, End: 165},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
		},
		{
			Name:      "slick-carousel",
			Version:   "1.7.1",
			Line:      models.Position{Start: 166, End: 175},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "280b560161b751ba226d50c7db1e0a14a78c2de0",
			DepGroups: []string{"dev"},
		},
	})
}

func TestParseNpmLock_v2_Files(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/files.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "etag",
			Version:   "1.8.0",
			Line:      models.Position{Start: 16, End: 35},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "abbrev",
			Version:   "1.0.9",
			Line:      models.Position{Start: 36, End: 41},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
			DepGroups: []string{"dev"},
		},
		{
			Name:      "abbrev",
			Version:   "2.3.4",
			Line:      models.Position{Start: 42, End: 47},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
			DepGroups: []string{"dev"},
		},
	})
}

func TestParseNpmLock_v2_Alias(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/alias.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@babel/code-frame",
			Version:   "7.0.0",
			Line:      models.Position{Start: 13, End: 21},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "string-width",
			Version:   "4.2.0",
			Line:      models.Position{Start: 32, End: 42},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "string-width",
			Version:   "5.1.2",
			Line:      models.Position{Start: 22, End: 31},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_OptionalPackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/optional-package.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Line:      models.Position{Start: 10, End: 15},
			Column:    models.Position{Start: 5, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			DepGroups: []string{"optional"},
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Line:      models.Position{Start: 16, End: 27},
			Column:    models.Position{Start: 6, End: 6},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			DepGroups: []string{"dev", "optional"},
		},
	})
}
