package testfixture

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

type Fixture struct {
	Path                string
	WindowsReplacements map[string]string
}

// applyWindowsReplacements will replace any matching strings if on Windows
func (s Fixture) applyWindowsReplacements(content string) string {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		for match, replacement := range s.WindowsReplacements {
			content = strings.ReplaceAll(content, match, replacement)
		}
	}

	return content
}

// load returns the contents of the fixture file after applying any replacements
// if on Windows
func (s Fixture) load(t *testing.T) []byte {
	t.Helper()

	var file []byte
	var err error

	file, err = os.ReadFile(s.Path)

	if err != nil {
		t.Fatalf("Failed to open fixture: %s", err)
	}

	return []byte(s.applyWindowsReplacements(string(file)))
}

func New(path string, windowsReplacements map[string]string) Fixture {
	return Fixture{Path: path, WindowsReplacements: windowsReplacements}
}

// LoadJSON returns the contents of the fixture file parsed as JSON after
// applying any replacements if running on Windows
func LoadJSON[V any](t *testing.T, fixture Fixture) V {
	t.Helper()

	file := fixture.load(t)

	var elem V
	err := json.Unmarshal(file, &elem)
	if err != nil {
		t.Fatalf("Failed to unmarshal val: %s", err)
	}

	return elem
}

// LoadText returns the contents of the fixture file as a string after
// applying any replacements if running on Windows
func LoadText(t *testing.T, fixture Fixture) string {
	t.Helper()

	return string(fixture.load(t))
}
