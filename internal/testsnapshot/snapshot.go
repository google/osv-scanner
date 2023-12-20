package testsnapshot

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

// "github.com/gkampitakis/go-snaps/match"
// "github.com/gkampitakis/go-snaps/snaps"

type Snapshot struct {
	Path                string
	WindowsReplacements map[string]string
}

// applyWindowsReplacements will replace any matching strings if on Windows
func (s Snapshot) applyWindowsReplacements(content string) string {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		for match, replacement := range s.WindowsReplacements {
			content = strings.ReplaceAll(content, match, replacement)
		}
	}

	return content
}

// load returns the contents of the snapshot file after applying any replacements
// if on Windows
func (s Snapshot) load(t *testing.T) []byte {
	t.Helper()

	var file []byte
	var err error

	file, err = os.ReadFile(s.Path)

	if err != nil {
		t.Fatalf("Failed to open snapshot: %s", err)
	}

	return []byte(s.applyWindowsReplacements(string(file)))
}

func New(path string, windowsReplacements map[string]string) Snapshot {
	return Snapshot{Path: path, WindowsReplacements: windowsReplacements}
}

// AssertJSON checks that the contents of the snapshot file parsed as JSON equals
// what was gotten in the test
func AssertJSON[V any](t *testing.T, snapshot Snapshot, got V) {
	t.Helper()

	j, err := json.Marshal(got)

	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}

	snaps.MatchSnapshot(t, snapshot.applyWindowsReplacements(string(j)))
}

func normalizeNewlines(content string) string {
	return strings.ReplaceAll(content, "\r\n", "\n")
}

// AssertText checks that the contents of the snapshot file equals what was
// gotten in the test
func AssertText(t *testing.T, snapshot Snapshot, got string) {
	t.Helper()

	// path := snapshot.Path
	// got = normalizeNewlines(got)
	// expect := normalizeNewlines(LoadText(t, snapshot))

	snaps.MatchSnapshot(t, snapshot.applyWindowsReplacements(got))

	// if got != expect {
	// 	if os.Getenv("TEST_NO_DIFF") == "true" {
	// 		t.Errorf("\ngot does not match snapshot at %s:\n got:\n%s\n\n want:\n%s", path, got, expect)
	// 	} else {
	// 		edits := myers.ComputeEdits(span.URIFromPath(path), expect, got)
	// 		diff := fmt.Sprint(gotextdiff.ToUnified("snapshot", "received", expect, edits))
	// 		t.Errorf("\ngot does not match snapshot at %s:\n%s", path, diff)
	// 	}
	// }
}
