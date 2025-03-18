package lockfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/internal/testutility"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/assert"
)

var gemspecFileMatcher = lockfile.GemspecFileMatcher{}

func TestGemspecFileMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := lockfile.OpenLocalDepFile("fixtures/bundler/no-gemspec/Gemfile.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := gemspecFileMatcher.GetSourceFile(lockFile)
	assert.Nil(t, sourceFile)
	assert.NoError(t, err)
}

func TestGemspecFileMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "fixtures/bundler/gemspec/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"test.gemspec"))

	lockFile, err := lockfile.OpenLocalDepFile(basePath + "Gemfile.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := gemspecFileMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestGemspecFileMatcher_Match(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/bundler/gemspec/test.gemspec")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "base64",
			Version:        "0.2.0",
			PackageManager: models.Bundler,
		},
		{
			Name:           "json",
			Version:        "2.9.1",
			PackageManager: models.Bundler,
		},
		{
			Name:           "thor",
			Version:        "1.3.2",
			PackageManager: models.Bundler,
		},
		{
			Name:           "timeout",
			Version:        "0.4.3",
			PackageManager: models.Bundler,
		},
		{
			Name:           "useragent",
			Version:        "0.16.11",
			PackageManager: models.Bundler,
		},
		{
			Name:           "websocket-driver",
			Version:        "0.7.7",
			PackageManager: models.Bundler,
		},
		{
			Name:           "websocket-extensions",
			Version:        "0.1.5",
			PackageManager: models.Bundler,
		},
		{
			Name:           "zeitwerk",
			Version:        "2.7.1",
			PackageManager: models.Bundler,
		},
	}

	err = gemspecFileMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().WithJSONNormalization().MatchJSON(t, packages)
}
