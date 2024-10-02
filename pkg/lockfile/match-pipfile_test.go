package lockfile_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/assert"
)

var pipfileMatcher = lockfile.PipfileMatcher{}

func TestPipfileMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := lockfile.OpenLocalDepFile("fixtures/pipfile/does-not-exist/Pipfile.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := pipfileMatcher.GetSourceFile(lockFile)
	expectErrIs(t, err, fs.ErrNotExist)
	assert.Equal(t, "", sourceFile.Path())
}

func TestPipfileMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "fixtures/pipfile/one-package/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"Pipfile"))

	lockFile, err := lockfile.OpenLocalDepFile(basePath + "Pipfile.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := pipfileMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestPipfileMatcher_Match_OnePackage(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/pipfile/one-package/Pipfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "markupsafe",
			PackageManager: models.Requirements,
		},
	}
	err = pipfileMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "markupsafe",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 17},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 11},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 15, End: 16},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestPipfileMatcher_Match_TransitiveDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/pipfile/transitive/Pipfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "asgiref",
			PackageManager: models.Requirements,
		},
		{
			Name:           "django",
			PackageManager: models.Requirements,
		},
		{
			Name:           "ply",
			PackageManager: models.Requirements,
		},
		{
			Name:           "sqlparse",
			PackageManager: models.Requirements,
		},
		{
			Name:           "typing-extensions",
			PackageManager: models.Requirements,
		},
	}
	err = pipfileMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "asgiref",
			PackageManager: models.Requirements,
		},
		{
			Name:           "django",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 16},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 11, End: 15},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "ply",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 13},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 4},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 8, End: 12},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "sqlparse",
			PackageManager: models.Requirements,
		},
		{
			Name:           "typing-extensions",
			PackageManager: models.Requirements,
		},
	})
}
