package testfixture

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

// applyWindowsReplacements will replace any matching strings if on Windows
func applyWindowsReplacements(content string, replacements map[string]string) string {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		for match, replacement := range replacements {
			content = strings.ReplaceAll(content, match, replacement)
		}
	}

	return content
}

// load returns the contents of the fixture file after applying any replacements if on Windows
func load(t *testing.T, path string, windowsReplacements map[string]string) []byte {
	t.Helper()

	var file []byte
	var err error

	file, err = os.ReadFile(path)

	if err != nil {
		t.Fatalf("Failed to open fixture: %s", err)
	}

	return []byte(applyWindowsReplacements(string(file), windowsReplacements))
}

// LoadJSON returns the contents of the fixture file parsed as JSON
func LoadJSON[V any](t *testing.T, path string) V {
	t.Helper()

	return LoadJSONWithWindowsReplacements[V](t, path, map[string]string{})
}

// LoadJSONWithWindowsReplacements returns the contents of the fixture file
// parsed as JSON after applying any replacements if running on Windows
func LoadJSONWithWindowsReplacements[V any](t *testing.T, path string, replacements map[string]string) V {
	t.Helper()

	file := load(t, path, replacements)

	var elem V
	err := json.Unmarshal(file, &elem)
	if err != nil {
		t.Fatalf("Failed to unmarshal val: %s", err)
	}

	return elem
}
