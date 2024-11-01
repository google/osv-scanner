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

var composerMatcher = lockfile.ComposerMatcher{}

func TestComposerMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := lockfile.OpenLocalDepFile("fixtures/composer/no-json/composer.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := composerMatcher.GetSourceFile(lockFile)
	expectErrIs(t, err, fs.ErrNotExist)
	assert.Equal(t, "", sourceFile.Path())
}

func TestComposerMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "fixtures/composer/one-package/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"composer.json"))

	lockFile, err := lockfile.OpenLocalDepFile(basePath + "composer.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := composerMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestComposerMatcher_Match_OnePackage(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/composer/one-package/composer.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "brick/math",
			Version:        "0.12.9",
			PackageManager: models.Composer,
			IsDirect:       true,
		},
	}
	err = composerMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}
