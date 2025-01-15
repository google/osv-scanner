package lockfile_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
)

func TestParseNuGetLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLock_v1_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/not-json.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLock_v1_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/empty.v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLock_v1_OneFramework_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/one-framework-one-package/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_OneFramework_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/one-framework-two-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "Test.System",
			Version:        "0.13.0-beta4",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_TwoFrameworks_MixedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/two-frameworks-mixed-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "Test.System",
			Version:        "0.13.0-beta4",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "Test.System",
			Version:        "2.15.0",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_TwoFrameworks_DifferentPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/two-frameworks-different-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "Test.System",
			Version:        "0.13.0-beta4",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_TwoFrameworks_DuplicatePackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/two-frameworks-duplicate-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_OneFramework_OnePackage_MatchedFailed(t *testing.T) {
	t.Parallel()

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	os.Stderr = w

	// Mock NugetCsprojMatcher to fail
	matcherError := errors.New("NugetCsprojMatcher failed")
	lockfile.NuGetExtractor.Matcher = FailingMatcher{Error: matcherError}

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/one-framework-one-package/packages.lock.json")
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
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
		},
	})
}
