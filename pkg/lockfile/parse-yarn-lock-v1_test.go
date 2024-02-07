package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseYarnLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v1_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/empty.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v1_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/one-package.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "balanced-match",
			Version:   "1.0.2",
			Line:      models.Position{Start: 5, End: 8},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/two-packages.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "concat-stream",
			Version:   "1.6.2",
			Line:      models.Position{Start: 10, End: 18},
			Column:    models.Position{Start: 1, End: 24},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "concat-map",
			Version:   "0.0.1",
			Line:      models.Position{Start: 5, End: 8},
			Column:    models.Position{Start: 1, End: 46},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_WithQuotes(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/with-quotes.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "concat-stream",
			Version:   "1.6.2",
			Line:      models.Position{Start: 10, End: 18},
			Column:    models.Position{Start: 1, End: 26},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "concat-map",
			Version:   "0.0.1",
			Line:      models.Position{Start: 5, End: 8},
			Column:    models.Position{Start: 1, End: 48},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_MultipleVersions(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/multiple-versions.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "define-properties",
			Version:   "1.1.3",
			Line:      models.Position{Start: 5, End: 10},
			Column:    models.Position{Start: 1, End: 26},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "define-property",
			Version:   "0.2.5",
			Line:      models.Position{Start: 12, End: 17},
			Column:    models.Position{Start: 1, End: 27},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "define-property",
			Version:   "1.0.0",
			Line:      models.Position{Start: 19, End: 24},
			Column:    models.Position{Start: 1, End: 27},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "define-property",
			Version:   "2.0.2",
			Line:      models.Position{Start: 26, End: 32},
			Column:    models.Position{Start: 1, End: 22},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_MultipleConstraints(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/multiple-constraints.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@babel/code-frame",
			Version:   "7.12.13",
			Line:      models.Position{Start: 10, End: 15},
			Column:    models.Position{Start: 1, End: 34},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "domelementtype",
			Version:   "1.3.1",
			Line:      models.Position{Start: 5, End: 8},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/scoped-packages.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@babel/code-frame",
			Version:   "7.12.11",
			Line:      models.Position{Start: 5, End: 10},
			Column:    models.Position{Start: 1, End: 33},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "@babel/compat-data",
			Version:   "7.14.0",
			Line:      models.Position{Start: 12, End: 15},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_WithPrerelease(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/with-prerelease.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "css-tree",
			Version:   "1.0.0-alpha.37",
			Line:      models.Position{Start: 5, End: 11},
			Column:    models.Position{Start: 1, End: 24},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "gensync",
			Version:   "1.0.0-beta.2",
			Line:      models.Position{Start: 13, End: 16},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "node-fetch",
			Version:   "3.0.0-beta.9",
			Line:      models.Position{Start: 18, End: 24},
			Column:    models.Position{Start: 1, End: 24},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "resolve",
			Version:   "1.20.0",
			Line:      models.Position{Start: 26, End: 32},
			Column:    models.Position{Start: 1, End: 24},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "resolve",
			Version:   "2.0.0-next.3",
			Line:      models.Position{Start: 34, End: 40},
			Column:    models.Position{Start: 1, End: 24},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_WithBuildString(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/with-build-string.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "domino",
			Version:   "2.1.6+git",
			Line:      models.Position{Start: 5, End: 8},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "tslib",
			Version:   "2.6.2",
			Line:      models.Position{Start: 10, End: 13},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}

func TestParseYarnLock_v1_Commits(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/commits.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "mine1",
			Version:   "1.0.0-alpha.37",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 5, End: 9},
			Column:    models.Position{Start: 1, End: 31},
			Commit:    "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
		},
		{
			Name:      "mine2",
			Version:   "0.0.1",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 11, End: 15},
			Column:    models.Position{Start: 1, End: 31},
			Commit:    "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
		},
		{
			Name:      "mine3",
			Version:   "1.2.3",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 17, End: 19},
			Column:    models.Position{Start: 1, End: 111},
			Commit:    "094e581aaf927d010e4b61d706ba584551dac502",
		},
		{
			Name:      "mine4",
			Version:   "0.0.2",
			Line:      models.Position{Start: 21, End: 23},
			Column:    models.Position{Start: 1, End: 101},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
		},
		{
			Name:      "mine4",
			Version:   "0.0.4",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 25, End: 27},
			Column:    models.Position{Start: 1, End: 111},
			Commit:    "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
		},
		{
			Name:      "my-package",
			Version:   "1.8.3",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 29, End: 31},
			Column:    models.Position{Start: 1, End: 103},
			Commit:    "b3bd3f1b3dad036e671251f5258beaae398f983a",
		},
		{
			Name:      "@bower_components/angular-animate",
			Version:   "1.4.14",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 33, End: 35},
			Column:    models.Position{Start: 1, End: 105},
			Commit:    "e7f778fc054a086ba3326d898a00fa1bc78650a8",
		},
		{
			Name:      "@bower_components/alertify",
			Version:   "0.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 37, End: 39},
			Column:    models.Position{Start: 1, End: 115},
			Commit:    "e7b6c46d76604d297c389d830817b611c9a8f17c",
		},
		{
			Name:      "minimist",
			Version:   "0.0.8",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 41, End: 43},
			Column:    models.Position{Start: 1, End: 93},
			Commit:    "3754568bfd43a841d2d72d7fb54598635aea8fa4",
		},
		{
			Name:      "bats-assert",
			Version:   "2.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 45, End: 47},
			Column:    models.Position{Start: 1, End: 95},
			Commit:    "4bdd58d3fbcdce3209033d44d884e87add1d8405",
		},
		{
			Name:      "bats-support",
			Version:   "0.3.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 49, End: 51},
			Column:    models.Position{Start: 1, End: 96},
			Commit:    "d140a65044b2d6810381935ae7f0c94c7023c8c3",
		},
		{
			Name:      "bats",
			Version:   "1.5.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 53, End: 55},
			Column:    models.Position{Start: 1, End: 93},
			Commit:    "172580d2ce19ee33780b5f1df817bbddced43789",
		},
		{
			Name:      "vue",
			Version:   "2.6.12",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 57, End: 59},
			Column:    models.Position{Start: 1, End: 87},
			Commit:    "bb253db0b3e17124b6d1fe93fbf2db35470a1347",
		},
		{
			Name:      "kit",
			Version:   "1.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 61, End: 66},
			Column:    models.Position{Start: 1, End: 32},
			Commit:    "5b6830c0252eb73c6024d40a8ff5106d3023a2a6",
		},
		{
			Name:      "casadistance",
			Version:   "1.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 68, End: 70},
			Column:    models.Position{Start: 1, End: 110},
			Commit:    "f0308391f0c50104182bfb2332a53e4e523a4603",
		},
		{
			Name:      "babel-preset-php",
			Version:   "1.1.1",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 72, End: 76},
			Column:    models.Position{Start: 1, End: 24},
			Commit:    "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
		},
		{
			Name:      "is-number",
			Version:   "2.0.0",
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Line:      models.Position{Start: 78, End: 80},
			Column:    models.Position{Start: 1, End: 113},
			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
		},
		{
			Name:      "is-number",
			Version:   "5.0.0",
			Line:      models.Position{Start: 82, End: 84},
			Column:    models.Position{Start: 1, End: 113},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
		},
	})
}

func TestParseYarnLock_v1_Files(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/files.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "etag",
			Version:   "1.8.1",
			Line:      models.Position{Start: 5, End: 7},
			Column:    models.Position{Start: 1, End: 105},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "filedep",
			Version:   "1.2.0",
			Line:      models.Position{Start: 9, End: 10},
			Column:    models.Position{Start: 1, End: 18},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "lodash",
			Version:   "1.3.1",
			Line:      models.Position{Start: 12, End: 14},
			Column:    models.Position{Start: 1, End: 109},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "other_package",
			Version:   "0.0.2",
			Line:      models.Position{Start: 16, End: 22},
			Column:    models.Position{Start: 1, End: 18},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "sprintf-js",
			Version:   "0.0.0",
			Line:      models.Position{Start: 24, End: 25},
			Column:    models.Position{Start: 1, End: 18},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
		{
			Name:      "etag",
			Version:   "1.8.0",
			Line:      models.Position{Start: 27, End: 28},
			Column:    models.Position{Start: 1, End: 18},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
			Commit:    "",
		},
	})
}

func TestParseYarnLock_v1_WithAliases(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/with-aliases.v1.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@babel/helper-validator-identifier",
			Version:   "7.22.20",
			Line:      models.Position{Start: 15, End: 18},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "ansi-regex",
			Version:   "6.0.1",
			Line:      models.Position{Start: 10, End: 13},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
		{
			Name:      "ansi-regex",
			Version:   "5.0.1",
			Line:      models.Position{Start: 5, End: 8},
			Column:    models.Position{Start: 1, End: 108},
			Ecosystem: lockfile.YarnEcosystem,
			CompareAs: lockfile.YarnEcosystem,
		},
	})
}
