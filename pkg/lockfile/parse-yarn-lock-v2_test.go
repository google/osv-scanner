package lockfile_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/stretchr/testify/assert"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseYarnLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v2_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseYarnLock("fixtures/yarn/empty.v2.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
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

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "balanced-match",
			Version:        "1.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

//nolint:paralleltest
func TestParseYarnLock_v2_OnePackage_MatcherFailed(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	os.Stderr = w

	// Mock packageJSONMatcher to fail
	matcherError := errors.New("packageJSONMatcher failed")
	lockfile.YarnExtractor.Matchers = []lockfile.Matcher{FailingMatcher{Error: matcherError}}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/one-package.v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Capture stderr
	_ = w.Close()
	os.Stderr = stderr
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, r)
	if err != nil {
		t.Errorf("failed to copy stderr output: %v", err)
	}
	_ = r.Close()

	assert.Contains(t, buffer.String(), matcherError.Error())
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "balanced-match",
			Version:        "1.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})

	// Reset packageJSONMatcher mock
	MockAllMatchers()
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

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "compare-func",
			Version:        "2.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.0.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "concat-map",
			Version:        "0.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.1"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
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

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "compare-func",
			Version:        "2.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.0.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "concat-map",
			Version:        "0.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.1"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
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

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "debug",
			Version:        "4.3.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"4", "^4.0.0", "^4.1.0", "^4.1.1", "^4.3.1", "^4.3.2", "^4.3.3"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "2.6.9",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.6.9"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "3.2.7",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^3.2.7"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
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

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@babel/cli",
			Version:        "7.16.8",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.4.4"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/code-frame",
			Version:        "7.16.7",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.0.0", "^7.12.13", "^7.16.7"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/compat-data",
			Version:        "7.16.8",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.13.11", "^7.16.4", "^7.16.8"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
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

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@nicolo-ribaudo/chokidar-2",
			Version:        "2.1.8-no-fsevents.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"2.1.8-no-fsevents.3"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "gensync",
			Version:        "1.0.0-beta.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0-beta.2"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "eslint-plugin-jest",
			Version:        "0.0.0-use.local",
			PackageManager: models.Yarn,
			TargetVersions: []string{"workspace:."},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
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

	expected := []lockfile.PackageDetails{
		{
			Name:           "domino",
			Version:        "2.1.6+git",
			Commit:         "f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/angular/domino.git#f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "tslib",
			Version:        "2.6.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.3.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "zone.js",
			Version:        "0.0.0-use.local",
			PackageManager: models.Yarn,
			TargetVersions: []string{"workspace:."},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}
	expected[2].Dependencies = append(expected[2].Dependencies, &expected[0], &expected[1])

	expectPackagesWithoutLocations(t, packages, expected)
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

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@my-scope/my-first-package",
			Version:        "0.0.6",
			PackageManager: models.Yarn,
			TargetVersions: []string{"my-scope/my-first-package#commit=0b824c650d3a03444dbcf2b27a5f3566f6e41358"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Commit:         "0b824c650d3a03444dbcf2b27a5f3566f6e41358",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "my-second-package",
			Version:        "0.2.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"my-org/my-second-package#commit=59e2127b9f9d4fda5f928c4204213b3502cd5bb0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Commit:         "59e2127b9f9d4fda5f928c4204213b3502cd5bb0",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@typegoose/typegoose",
			Version:        "7.2.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/typegoose/typegoose.git#main"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Commit:         "3ed06e5097ab929f69755676fee419318aaec73a",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "vuejs",
			Version:        "2.5.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/vuejs/vue.git"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Commit:         "0948d999f2fddf9f90991956493f976273c5da1f",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "my-third-package",
			Version:        "0.16.1-dev",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/my-org/my-third-package#everything"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Commit:         "5675a0aed98e067ff6ecccc5ac674fe8995960e0",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "my-node-sdk",
			Version:        "1.1.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"git+https://github.com/my-org/my-node-sdk.git#v1.1.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Commit:         "053dea9e0b8af442d8f867c8e690d2fb0ceb1bf5",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "is-really-great",
			Version:        "1.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"ssh://git@github.com:my-org/is-really-great.git"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Commit:         "191eeef50c584714e1fb8927d17ee72b3b8c97c4",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
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

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "my-package",
			Version:        "0.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"../../deps/my-local-package"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
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

	expected := []lockfile.PackageDetails{
		{
			Name:           "@babel/helper-validator-identifier",
			Version:        "7.22.20",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.0.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "ansi-regex",
			Version:        "6.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^6.0.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "ansi-regex",
			Version:        "5.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "mine",
			Version:        "0.0.0-use.local",
			PackageManager: models.Yarn,
			TargetVersions: []string{"workspace:."},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}
	expected[3].Dependencies = append(expected[3].Dependencies, &expected[1])

	expectPackagesWithoutLocations(t, packages, expected)
}

func TestParseYarnLock_v2_WithDependencies(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/yarn/with-dependencies-v2.lock"))
	packages, err := lockfile.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "domino",
			Version:        "2.1.6+git",
			Commit:         "f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a",
			TargetVersions: []string{"https://github.com/angular/domino.git#f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "tslib",
			Version:        "2.6.2",
			TargetVersions: []string{"^2.3.0"},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "zone.js",
			Version:        "0.0.0-use.local",
			TargetVersions: []string{"workspace:."},
			Ecosystem:      lockfile.YarnEcosystem,
			CompareAs:      lockfile.YarnEcosystem,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}
	expected[0].Dependencies = append(expected[0].Dependencies, &expected[1])
	expected[2].Dependencies = append(expected[2].Dependencies, &expected[0], &expected[1])

	expectPackagesWithoutLocations(t, packages, expected)
}
