package lockfile_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

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
			PackageManager: models.NPM,
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
			PackageManager: models.NPM,
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
			PackageManager: models.NPM,
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
			PackageManager: models.NPM,
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

func TestPackageJSONMatcher_Match_Target_Version(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/multiple-versions/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "foo",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1.0.0 - 2.9999.9999"},
		},
		{
			Name:           "bar",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{">=1.0.2 <2.1.2"},
		},
		{
			Name:           "baz",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{">1.0.2 <=2.3.4"},
		},
		{
			Name:           "boo",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1.5.3"},
		},
		{
			Name:           "qux",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"<1.0.0 || >=2.3.1 <2.4.5 || >=2.5.2 <3.0.0"},
		},
		{
			Name:           "asd",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"http://asdf.com/asdf.tar.gz"},
		},
		{
			Name:           "til",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"~1.5"},
		},
		{
			Name:           "elf",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"~1.5.3"},
		},
		{
			Name:           "two",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1.x"},
		},
		{
			Name:           "thr",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1.5.x"},
		},
		{
			Name:           "lat",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"latest"},
		},
		{
			Name:           "dyl",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"file:../dyl"},
		},
		{
			Name:           "kpg",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"npm:pkg@1.5.0"},
		},
		{
			Name:           "abc",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1"},
		},
		{
			Name:           "cde",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{">1.0.2"},
		},
		{
			Name:           "dd",
			Version:        "0.0.0-use.local",
			PackageManager: models.NPM,
			TargetVersions: []string{"javascript/datadog"},
		},
		{
			Name:           "dd2",
			Version:        "0.0.0-use.local",
			PackageManager: models.NPM,
			TargetVersions: []string{"javascript/datadog"},
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}
