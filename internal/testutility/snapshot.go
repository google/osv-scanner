package testutility

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type Snapshot struct {
	windowsReplacements map[string]string
}

// NewSnapshot creates a snapshot that can be passed around within tests
func NewSnapshot() Snapshot {
	return Snapshot{windowsReplacements: map[string]string{}}
}

// WithWindowsReplacements adds a map of strings with values that they should be
// replaced within before comparing the snapshot when running on Windows
func (s Snapshot) WithWindowsReplacements(replacements map[string]string) Snapshot {
	s.windowsReplacements = replacements

	return s
}

// WithCRLFReplacement adds a Windows replacement for "\r\n" to "\n".
// This should be called after WithWindowsReplacements if used together.
func (s Snapshot) WithCRLFReplacement() Snapshot {
	s.windowsReplacements["\r\n"] = "\n"

	return s
}

// MatchJSON asserts the existing snapshot matches what was gotten in the test,
// after being marshalled as JSON
func (s Snapshot) MatchJSON(t *testing.T, got any) {
	t.Helper()

	j, err := json.MarshalIndent(got, "", "  ")

	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}

	s.MatchText(t, string(j))
}

// MatchText asserts the existing snapshot matches what was gotten in the test
func (s Snapshot) MatchText(t *testing.T, got string) {
	t.Helper()

	snaps.MatchSnapshot(t, applyWindowsReplacements(got, s.windowsReplacements))
}

// MatchText asserts the existing snapshot matches what was gotten in the test
func (s Snapshot) MatchOSVScannerJSONOutput(t *testing.T, jsonInput string, jsonReplaceRules ...JSONReplaceRule) {
	t.Helper()

	for _, rule := range jsonReplaceRules {
		jsonInput = replaceJSONInput(t, jsonInput, rule.Path, rule.ReplaceFunc)
	}

	snaps.MatchJSON(t, jsonInput)
}

func replaceJSONInput(t *testing.T, jsonInput, path string, matcher func(toReplace gjson.Result) any) string {
	pathArray := []string{}

	// If there are more than 2 #, sjson cannot replace them directly. Iterate out all individual entries
	if strings.Contains(path, "#") {
		// Get the path ending with #
		// E.g. results.#.packages.#.vulnerabilities => results.#.packages.#
		numOfEntriesPath := path[:strings.LastIndex(path, "#")+1]
		// This returns a potentially nested array of array lengths
		numOfEntries := gjson.Get(jsonInput, numOfEntriesPath)

		// Use it to build up a list of concrete paths
		buildSJSONPaths(t, &pathArray, path, numOfEntries)
	} else {
		pathArray = append(pathArray, path)
	}

	var err error
	json := jsonInput
	for _, pathElem := range pathArray {
		res := gjson.Get(jsonInput, pathElem)
		// TODO: Optimize with byte arrays instead
		json, err = sjson.SetOptions(json, pathElem, matcher(res), &sjson.Options{Optimistic: true})
		if err != nil {
			t.Fatalf("failed to set element")
		}
	}

	return json
}

func buildSJSONPaths(t *testing.T, pathToBuild *[]string, path string, structure gjson.Result) {
	if structure.IsArray() {
		// More nesting to go
		for i, res := range structure.Array() {
			buildSJSONPaths(
				t,
				pathToBuild,
				// Replace the first # with actual index
				strings.Replace(path, "#", strconv.Itoa(i), 1),
				res,
			)
		}
	} else {
		// Otherwise assume it is a number
		if strings.Count(path, "#") != 1 {
			t.Fatalf("programmer error: there should only be 1 # left")
		}
		for i2 := 0; i2 < int(structure.Int()); i2++ {
			newPath := strings.Replace(path, "#", strconv.Itoa(i2), 1)
			*pathToBuild = append(*pathToBuild, newPath)
		}
	}
}
