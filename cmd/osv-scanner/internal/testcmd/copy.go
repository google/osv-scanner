package testcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func CopyFileTo(t *testing.T, file, dir string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("could not read test file: %v", err)
	}

	dst := filepath.Join(dir, filepath.Base(file))
	if err := os.WriteFile(dst, b, 0600); err != nil {
		t.Fatalf("could not copy test file: %v", err)
	}

	return dst
}
