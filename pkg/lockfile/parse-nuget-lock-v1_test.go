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
	nuGetExtractor := lockfile.NuGetLockExtractor{
		WithMatcher: lockfile.WithMatcher{Matchers: []lockfile.Matcher{FailingMatcher{Error: matcherError}}},
	}

	packages, err := lockfile.ExtractFromFile("fixtures/nuget/one-framework-one-package/packages.lock.json", nuGetExtractor)
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

func TestParseNuGetLock_v1_DevelopmentDependency(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/development-dependency-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	absoluteCsprojPath, err := filepath.Abs("fixtures/nuget/development-dependency-packages/development-dependency.csproj")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Microsoft.TestPlatform.TestHost",
			Version:        "17.12.0",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
			DepGroups:      []string{string(lockfile.DepGroupDev)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 13},
				Column:   models.Position{Start: 3, End: 22},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 30, End: 61},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 72, End: 79},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
			DepGroups:      []string{string(lockfile.DepGroupDev)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 3, End: 79},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 30, End: 39},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 50, End: 75},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Test.System",
			Version:        "0.13.0-beta4",
			PackageManager: models.NuGet,
			Ecosystem:      lockfile.NuGetEcosystem,
			CompareAs:      lockfile.NuGetEcosystem,
			IsDirect:       true,
			DepGroups:      []string{string(lockfile.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 3, End: 68},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 30, End: 41},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 52, End: 64},
				Filename: absoluteCsprojPath,
			},
		},
	})
}
