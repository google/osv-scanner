package sourceanalysis

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func Test_extractRlibArchive(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("fixtures-rust/archives")
	if err != nil {
		t.Error(err)
	}
	for _, file := range entries {
		filename := file.Name()
		t.Run("Extract Rlib "+filename, func(t *testing.T) {
			t.Parallel()
			buf, err := extractRlibArchive(filepath.Join("fixtures-rust/archives", file.Name()))
			if err != nil {
				t.Error(err)
			}

			expectedFileName := strings.Replace(file.Name(), ".rlib", ".o", 1)
			expectedBuf, err := os.ReadFile(filepath.Join("fixtures-rust/objs", expectedFileName))
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(buf.Bytes(), expectedBuf) {
				t.Fatalf("Extracted not identical to expected: %s", filepath.Join("fixtures-rust/archives", file.Name()))
			}
		})
	}
}
