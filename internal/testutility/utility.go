package testutility

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
)

func determineWindowsFixturePath(t *testing.T, path string) string {
	t.Helper()

	ext := filepath.Ext(path)

	return strings.TrimSuffix(path, ext) + "_windows" + ext
}

func loadFixture(t *testing.T, path string) ([]byte, string) {
	t.Helper()

	var file []byte
	var err error

	// when on Windows, check if there is a version of the fixture whose filename
	// ends with _windows and if so use that instead
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		winFixturePath := determineWindowsFixturePath(t, path)

		file, err = os.ReadFile(winFixturePath)

		if err == nil {
			return file, winFixturePath
		}
		// load the original file if a Windows-specific version does not exist
		if !os.IsNotExist(err) {
			t.Fatalf("Failed to open fixture: %s", err)
		}
	}

	file, err = os.ReadFile(path)

	if err != nil {
		t.Fatalf("Failed to open fixture: %s", err)
	}

	return file, path
}

// LoadJSONFixture loads a JSON fixture file and returns the decoded version.
func LoadJSONFixture[V any](t *testing.T, path string) V {
	t.Helper()

	file, _ := loadFixture(t, path)

	var elem V
	err := json.Unmarshal(file, &elem)
	if err != nil {
		t.Fatalf("Failed to unmarshal val: %s", err)
	}

	return elem
}

// AssertMatchFixtureJSON matches the JSON at path with the value val, failing if not equal, printing out the difference.
func AssertMatchFixtureJSON[V any](t *testing.T, path string, val V) {
	t.Helper()

	elem := LoadJSONFixture[V](t, path)

	if !reflect.DeepEqual(val, elem) {
		t.Errorf("Not equal: \n%s", cmp.Diff(val, elem))
	}
}

// CreateJSONFixture creates a JSON file at path of the value val,
// can be used with AssertMatchFixtureJSON to compare against future values.
func CreateJSONFixture[V any](t *testing.T, path string, val V) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to open file to write: %s", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(val)
	if err != nil {
		t.Fatalf("Failed to encode val: %s", err)
	}
}

// CreateTextFixture creates a text file at path of the value val,
// can be used with AssertMatchFixtureJSON to compare against future values.
func CreateTextFixture(t *testing.T, path string, val string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to open file to write: %s", err)
	}

	_, err = file.WriteString(val)
	if err != nil {
		t.Fatalf("Failed to write string to file: %s", err)
	}
}

func normalizeNewlines(content string) string {
	return strings.ReplaceAll(content, "\r\n", "\n")
}

// AssertMatchFixtureText matches the Text file at path with actual
func AssertMatchFixtureText(t *testing.T, path string, actual string) {
	t.Helper()

	fileA, path := loadFixture(t, path)

	actual = normalizeNewlines(actual)
	expect := string(fileA)
	expect = normalizeNewlines(expect)
	if actual != expect {
		if os.Getenv("TEST_NO_DIFF") == "true" {
			t.Errorf("\nactual %s does not match expected:\n got:\n%s\n\n want:\n%s", path, actual, expect)
		} else {
			edits := myers.ComputeEdits(span.URIFromPath(path), expect, actual)
			diff := fmt.Sprint(gotextdiff.ToUnified(path, "test-output", expect, edits))
			t.Errorf("\nactual %s does not match expected:\n%s", path, diff)
		}
	}
}

// AcceptanceTests marks this test function as a extended that require additional dependencies
// automatically skipped unless running in a CI environment
func AcceptanceTests(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("TEST_ACCEPTANCE") != "true" {
		t.Skip("Skipping extended test: ", reason)
	}
}

func ValueIfOnWindows(win, or string) string {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		return win
	}

	return or
}
