package lockfile_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseYarnLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v2_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/empty.v2.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v2_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/one-package.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "balanced-match",
			Version: "1.0.2",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 13},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v2_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/two-packages.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "compare-func",
			Version: "2.0.0",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 16},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "concat-map",
			Version: "0.0.1",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 23},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v2_WithQuotes(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/with-quotes.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "compare-func",
			Version: "2.0.0",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 16},
				Column:   models.Position{Start: 1, End: 19},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "concat-map",
			Version: "0.0.1",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 23},
				Column:   models.Position{Start: 1, End: 19},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v2_MultipleVersions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/multiple-versions.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "debug",
			Version: "4.3.3",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 18},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "debug",
			Version: "2.6.9",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 20, End: 27},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "debug",
			Version: "3.2.7",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 29, End: 36},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v2_ScopedPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/scoped-packages.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "@babel/cli",
			Version: "7.16.8",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 33},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "@babel/code-frame",
			Version: "7.16.7",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 35, End: 42},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "@babel/compat-data",
			Version: "7.16.8",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 44, End: 49},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v2_WithPrerelease(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/with-prerelease.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "@nicolo-ribaudo/chokidar-2",
			Version: "2.1.8-no-fsevents.3",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 13},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "gensync",
			Version: "1.0.0-beta.2",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 15, End: 20},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "eslint-plugin-jest",
			Version: "0.0.0-use.local",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 22, End: 76},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v2_WithBuildString(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/with-build-string.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "domino",
			Version: "2.1.6+git",
			Commit:  "f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 13},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "tslib",
			Version: "2.6.2",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 15, End: 20},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "zone.js",
			Version: "0.0.0-use.local",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 22, End: 29},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v2_Commits(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/commits.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@my-scope/my-first-package",
			Version:   "0.0.6",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 10},
				Column:   models.Position{Start: 1, End: 138},
				Filename: path,
			},
			Commit: "0b824c650d3a03444dbcf2b27a5f3566f6e41358",
		},
		{
			Name:      "my-second-package",
			Version:   "0.2.2",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 19},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Commit: "59e2127b9f9d4fda5f928c4204213b3502cd5bb0",
		},
		{
			Name:      "@typegoose/typegoose",
			Version:   "7.2.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 21, End: 35},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Commit: "3ed06e5097ab929f69755676fee419318aaec73a",
		},
		{
			Name:      "vuejs",
			Version:   "2.5.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 37, End: 42},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Commit: "0948d999f2fddf9f90991956493f976273c5da1f",
		},
		{
			Name:      "my-third-package",
			Version:   "0.16.1-dev",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 45, End: 47},
				Column:   models.Position{Start: 1, End: 128},
				Filename: path,
			},
			Commit: "5675a0aed98e067ff6ecccc5ac674fe8995960e0",
		},
		{
			Name:      "my-node-sdk",
			Version:   "1.1.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 50, End: 55},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Commit: "053dea9e0b8af442d8f867c8e690d2fb0ceb1bf5",
		},
		{
			Name:      "is-really-great",
			Version:   "1.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 58, End: 63},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Commit: "191eeef50c584714e1fb8927d17ee72b3b8c97c4",
		},
	})
}

func TestParseYarnLock_v2_Files(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/files.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "my-package",
			Version: "0.0.2",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 13},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
	})
}

func TestParseYarnLock_v2_WithAliases(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/with-aliases.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:    "@babel/helper-validator-identifier",
			Version: "7.22.20",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 22, End: 27},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "ansi-regex",
			Version: "6.0.1",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 15, End: 20},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "ansi-regex",
			Version: "5.0.1",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 13},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:    "mine",
			Version: "0.0.0-use.local",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 29, End: 37},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}
