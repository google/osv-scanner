package testsnapshot

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

type Snapshot struct {
	WindowsReplacements map[string]string
}

// applyWindowsReplacements will replace any matching strings if on Windows
func (s Snapshot) applyWindowsReplacements(content string) string {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		for replacement, match := range s.WindowsReplacements {
			content = strings.ReplaceAll(content, match, replacement)
		}
	}

	return content
}

// New creates a snapshot that can be passed around within tests
func New() Snapshot {
	return Snapshot{WindowsReplacements: map[string]string{}}
}

// WithWindowsReplacements adds a map of strings with values that they should be
// replaced within before comparing the snapshot when running on Windows
func (s Snapshot) WithWindowsReplacements(replacements map[string]string) Snapshot {
	s.WindowsReplacements = replacements

	return s
}

// MatchJSON asserts the existing snapshot matches what was gotten in the test,
// after being marshalled as JSON
func (s Snapshot) MatchJSON(t *testing.T, got any) {
	t.Helper()

	j, err := json.Marshal(got)

	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}

	s.MatchText(t, string(j))
}

// MatchText asserts the existing snapshot matches what was gotten in the test
func (s Snapshot) MatchText(t *testing.T, got string) {
	t.Helper()

	snaps.MatchSnapshot(t, s.applyWindowsReplacements(got))
}
