package lockfile_test

import (
	"io/fs"
	"os"
	"path/filepath"
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

	expectErrContaining(t, err, "could not extract from")
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
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/one-package.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParseNpmLock_v1_OnePackageDev(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/one-package-dev.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParseNpmLock_v1_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/two-packages.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "supports-color",
			Version:        "5.5.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParseNpmLock_v1_ScopedPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/scoped-packages.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "@babel/code-frame",
			Version:        "7.0.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParseNpmLock_v1_NestedDependencies(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/nested-dependencies.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "postcss",
			Version:        "6.0.23",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "postcss",
			Version:        "7.0.16",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "postcss-calc",
			Version:        "7.0.1",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "supports-color",
			Version:        "6.1.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "supports-color",
			Version:        "5.5.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParseNpmLock_v1_NestedDependenciesDup(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/nested-dependencies-dup.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// todo: convert to using expectPackages w/ listing all expected packages
	if len(packages) != 39 {
		t.Errorf("Expected to get 39 packages, but got %d", len(packages))
	}

	expectPackage(t, packages, lockfile.PackageDetails{
		Name:           "supports-color",
		Version:        "6.1.0",
		PackageManager: models.NPM,
		Ecosystem:      lockfile.NpmEcosystem,
		CompareAs:      lockfile.NpmEcosystem,
		DepGroups:      []string{"prod"},
	})

	expectPackage(t, packages, lockfile.PackageDetails{
		Name:           "supports-color",
		Version:        "5.5.0",
		PackageManager: models.NPM,
		Ecosystem:      lockfile.NpmEcosystem,
		CompareAs:      lockfile.NpmEcosystem,
		DepGroups:      []string{"prod"},
	})

	expectPackage(t, packages, lockfile.PackageDetails{
		Name:           "supports-color",
		Version:        "2.0.0",
		PackageManager: models.NPM,
		Ecosystem:      lockfile.NpmEcosystem,
		CompareAs:      lockfile.NpmEcosystem,
		DepGroups:      []string{"prod"},
	})
}

func TestParseNpmLock_v1_Commits(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/commits.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@segment/analytics.js-integration-facebook-pixel",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "ansi-styles",
			Version:        "1.0.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "babel-preset-php",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "is-number-1",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-1",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "be5935f8d2595bcd97b05718ef1eeae08d812e10",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-2",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "is-number-2",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "82dcc8e914dabd9305ab9ae580709a7825e824f5",
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "is-number-3",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-3",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-4",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-5",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-6",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "postcss-calc",
			Version:        "7.0.1",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "raven-js",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "slick-carousel",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "280b560161b751ba226d50c7db1e0a14a78c2de0",
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParseNpmLock_v1_Files(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/files.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "lodash",
			Version:        "1.3.1",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "other_package",
			Version:        "",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParseNpmLock_v1_Alias(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/alias.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@babel/code-frame",
			Version:        "7.0.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "string-width",
			Version:        "4.2.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "string-width",
			Version:        "5.1.2",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParseNpmLock_v1_OptionalPackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/optional-package.v1.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"optional", "dev"},
		},
		{
			Name:           "supports-color",
			Version:        "5.5.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"optional", "prod"},
		},
	})
}

func TestParseNpmLock_v1_SamePackageDifferentGroups(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/same-package-different-groups.v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "eslint",
			Version:        "1.2.3",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "table",
			Version:        "1.0.0",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "ajv",
			Version:        "5.5.2",
			PackageManager: models.NPM,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			DepGroups:      []string{"dev", "optional", "prod"},
		},
	})
}
