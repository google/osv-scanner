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

	expectErrContaining(t, err, "could not extract from")
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
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pipenv/one-package.json"))
	packages, err := lockfile.ParsePipenvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "markupsafe",
			Version:        "2.1.1",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
		},
	})
}

//nolint:paralleltest
func TestParsePipenvLock_OnePackage_MatcherFailed(t *testing.T) {
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

	// Mock pipfileMatcher to fail
	matcherError := errors.New("pipfileMatcher failed")
	lockfile.PipenvExtractor.Matchers = []lockfile.Matcher{FailingMatcher{Error: matcherError}}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pipenv/one-package.json"))
	packages, err := lockfile.ParsePipenvLock(path)
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
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "markupsafe",
			Version:        "2.1.1",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
		},
	})

	// Reset pipfileMatcher mock
	MockAllMatchers()
}

func TestParsePipenvLock_OnePackageDev(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pipenv/one-package-dev.json"))
	packages, err := lockfile.ParsePipenvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "markupsafe",
			Version:        "2.1.1",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParsePipenvLock_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pipenv/two-packages.json"))
	packages, err := lockfile.ParsePipenvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "itsdangerous",
			Version:        "2.1.2",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
		},
		{
			Name:           "markupsafe",
			Version:        "2.1.1",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParsePipenvLock_TwoPackagesAlt(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pipenv/two-packages-alt.json"))
	packages, err := lockfile.ParsePipenvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "itsdangerous",
			Version:        "2.1.2",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
		},
		{
			Name:           "markupsafe",
			Version:        "2.1.1",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
		},
	})
}

func TestParsePipenvLock_MultiplePackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pipenv/multiple-packages.json"))
	packages, err := lockfile.ParsePipenvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "itsdangerous",
			Version:        "2.1.2",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
		},
		{
			Name:           "pluggy",
			Version:        "1.0.1",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
		},
		{
			Name:           "pluggy",
			Version:        "1.0.0",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "markupsafe",
			Version:        "2.1.1",
			PackageManager: models.Pipfile,
			Ecosystem:      lockfile.PipenvEcosystem,
			CompareAs:      lockfile.PipenvEcosystem,
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
