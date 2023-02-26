package testutility

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kr/pretty"
)

// LoadHelper loads a JSON fixture file and returns the decoded version.
func LoadHelper[V any](t *testing.T, path string) V {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open fixture: %s", err)
	}
	var value V
	err = json.NewDecoder(file).Decode(&value)
	if err != nil {
		t.Fatalf("Failed to parse fixture: %s", err)
	}

	return value
}

// AssertMatchFixtureJSON matches the JSON at path with the value val, failing if not equal, printing out the difference.
func AssertMatchFixtureJSON[V any](t *testing.T, path string, val V) {
	fileA, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to open fixture: %s", err)
	}

	var elem V
	json.Unmarshal(fileA, &elem)

	if !reflect.DeepEqual(val, elem) {
		t.Fatalf("Not equal: \n%s", strings.Join(pretty.Diff(val, elem), "\n"))
	}
}

// AssertMatchFixtureJSON creates a JSON file at path of the value val,
// can be used with AssertMatchFixtureJSON to compare against future values.
func CreateJSONSnapshot[V any](t *testing.T, path string, val V) {
	file, err := os.Open(path)
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
