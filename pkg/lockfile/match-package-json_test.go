package lockfile_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/internal/testutility"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
)

var packageJSONMatcher = lockfile.PackageJSONMatcher{}

func TestPackageJSONMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/does-not-exist/npm-v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := packageJSONMatcher.GetSourceFile(lockFile)
	expectErrIs(t, err, fs.ErrNotExist)
	assert.Equal(t, "", sourceFile.Path())
}

func TestPackageJSONMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "fixtures/package-json/one-package/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"package.json"))

	lockFile, err := lockfile.OpenLocalDepFile(basePath + "npm-v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := packageJSONMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestPackageJSONMatcher_Match_OnePackage(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/one-package/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "lodash",
			TargetVersions: []string{"^4.0.0"},
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}

func TestPackageJSONMatcher_Match_TransitiveDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/transitive/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "commander",
			TargetVersions: []string{"~2.0.0"},
		},
		{
			Name:           "debug",
			TargetVersions: []string{"^0.7", "~0.7.2"},
		},
		{
			Name:           "jear",
			TargetVersions: []string{"^0.1.4"},
		},
		{
			Name:           "shelljs",
			TargetVersions: []string{"~0.1.4"},
		},
		{
			Name:           "velocityjs",
			TargetVersions: []string{"~0.3.15"},
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}

func TestPackageJSONMatcher_Match_NameConflict(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/name-conflict/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "aws-sdk-client-mock",
			TargetVersions: []string{"^2.1.1"},
		},
		{
			Name:           "aws-sdk-client-mock-jest",
			TargetVersions: []string{"^2.1.1"},
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}

func TestPackageJSONMatcher_Match_Resolutions(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/resolutions/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "fast-xml-parser",
			Version:        "4.2.5",
			TargetVersions: []string{"4.2.5"},
		},
		{
			Name:           "fast-xml-parser",
			Version:        "4.4.0",
			TargetVersions: []string{"^4.2.5"},
		},
		{
			Name:           "@aws-sdk/core",
			Version:        "3.535.0",
			TargetVersions: []string{"^3.535.0"},
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}
