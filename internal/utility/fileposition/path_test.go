package fileposition

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveHostPath(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	scanPath := "."
	packagePath := filepath.FromSlash(filepath.Join(dir, "path_test.go"))

	assert.Equal(t, "path_test.go", ToRelativePath(scanPath, packagePath))
}
