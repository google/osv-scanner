package lockfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
)

var nugetCsprojMatcher = lockfile.NugetCsprojMatcher{}

func TestNugetCsprojMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/does-not-exist/npm-v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := nugetCsprojMatcher.GetSourceFile(lockFile)
	assert.Equal(t, "no csproj file found", err.Error())
	assert.Nil(t, sourceFile)
}

func TestNugetCsprojMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()

	lockFile, err := lockfile.OpenLocalDepFile("fixtures/nuget/one-framework-one-package.v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := nugetCsprojMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "fixtures/nuget/"
	sourceFilePath := filepath.FromSlash(filepath.Join(dir, basePath+"project.csproj"))

	assert.Equal(t, sourceFile.Path(), sourceFilePath)
}

func TestNugetCsprojMatcher_Match_Packages(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/nuget/project.csproj")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "Downloader",
			PackageManager: models.NuGet,
		},
		{
			Name:           "MaterialDesignThemes",
			PackageManager: models.NuGet,
		},
		{
			Name:           "Test.Core",
			PackageManager: models.NuGet,
		},
	}
	err = nugetCsprojMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "fixtures/nuget/"
	sourceFilePath := filepath.FromSlash(filepath.Join(dir, basePath+"project.csproj"))

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Downloader",
			PackageManager: models.NuGet,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 3, End: 58},
				Filename: sourceFilePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 51, End: 54},
				Filename: sourceFilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 30, End: 40},
				Filename: sourceFilePath,
			},
		},
		{
			Name:           "MaterialDesignThemes",
			PackageManager: models.NuGet,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 3, End: 70},
				Filename: sourceFilePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 61, End: 66},
				Filename: sourceFilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 30, End: 50},
				Filename: sourceFilePath,
			},
		},
		{
			Name:           "Test.Core",
			PackageManager: models.NuGet,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 16},
				Column:   models.Position{Start: 5, End: 24},
				Filename: sourceFilePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 21},
				Filename: sourceFilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 16, End: 25},
				Filename: sourceFilePath,
			},
		},
	})
}
