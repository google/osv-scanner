package sourceanalysis

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
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
			buf, err := extractRlibArchive(filepath.Join("fixtures-rust/archives", filename))
			if err != nil {
				t.Error(err)
			}

			expectedFileName := strings.Replace(filename, ".rlib", ".o", 1)
			expectedBuf, err := os.ReadFile(filepath.Join("fixtures-rust/objs", expectedFileName))
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(buf.Bytes(), expectedBuf) {
				t.Fatalf("Extracted not identical to expected: %s", filepath.Join("fixtures-rust/archives", filename))
			}
		})
	}
}

func Test_functionsFromDWARF(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("fixtures-rust/objs")
	if err != nil {
		t.Error(err)
	}
	for _, file := range entries {
		filename := file.Name()
		t.Run("Parsing DWARF "+filename, func(t *testing.T) {
			t.Parallel()
			buf, err := os.ReadFile(filepath.Join("fixtures-rust/objs", filename))
			if err != nil {
				t.Error(err)
			}
			functions, err := functionsFromDWARF(bytes.NewReader(buf))
			if err != nil {
				t.Error(err)
			}

			outputName := strings.TrimSuffix(filename, ".o") + ".json"

			testutility.AssertMatchFixtureJSON(t, "fixtures-rust/functions/"+outputName, functions)
		})
	}
}
