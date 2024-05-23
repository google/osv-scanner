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

	testCases := []struct {
		considerScanPathAsRoot bool
		pathRelativeToScanDir  bool
		path                   string
	}{
		{
			considerScanPathAsRoot: false,
			pathRelativeToScanDir:  false,
			path:                   packagePath,
		},
		{
			considerScanPathAsRoot: false,
			pathRelativeToScanDir:  true,
			path:                   "path_test.go",
		},
		{
			considerScanPathAsRoot: true,
			pathRelativeToScanDir:  false,
			path:                   "/path_test.go",
		},
		{
			considerScanPathAsRoot: true,
			pathRelativeToScanDir:  true,
			path:                   "path_test.go",
		},
	}

	for _, tt := range testCases {
		assert.Equal(t, tt.path, RemoveHostPath(scanPath, packagePath, tt.considerScanPathAsRoot, tt.pathRelativeToScanDir))
	}
}
