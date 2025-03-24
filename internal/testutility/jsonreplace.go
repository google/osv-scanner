package testutility

import (
	"strconv"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type JSONReplaceRule struct {
	Path        string
	ReplaceFunc func(toReplace gjson.Result) any
}

var (
	OnlyIDVulnsRule = JSONReplaceRule{
		Path: "results.#.packages.#.vulnerabilities",
		ReplaceFunc: func(toReplace gjson.Result) any {
			return toReplace.Get("#.id").Value()
		},
	}
	GroupsAsArrayLen = JSONReplaceRule{
		Path: "results.#.packages.#.groups",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if toReplace.IsArray() {
				return len(toReplace.Array())
			}

			return 0
		},
	}
	OnlyFirstBaseImage = JSONReplaceRule{
		Path: "image_metadata.base_images.#",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if toReplace.IsArray() && len(toReplace.Array()) >= 1 {
				return toReplace.Array()[0].Value()
			}

			return struct{}{}
		},
	}
	AnyDiffID = JSONReplaceRule{
		Path: "image_metadata.layer_metadata.#.diff_id",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if len(toReplace.String()) > 7 {
				return toReplace.String()[:7] + "..."
			}

			return ""
		},
	}
	ShortenHistoryCommandLength = JSONReplaceRule{
		Path: "image_metadata.layer_metadata.#.command",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if len(toReplace.String()) > 28 {
				return toReplace.String()[:25] + "..."
			}

			return toReplace.String()
		},
	}
	// Older and newer versions of docker has different COMMAND histories
	NormalizeHistoryCommand = JSONReplaceRule{
		Path: "image_metadata.layer_metadata.#.command",
		ReplaceFunc: func(toReplace gjson.Result) any {
			str := toReplace.String()
			nopMatcher := cachedregexp.MustCompile(`^/bin/sh -c #\(nop\)\s+`)
			runMatcher := cachedregexp.MustCompile(`^/bin/sh -c\s+`)
			str = nopMatcher.ReplaceAllLiteralString(str, "")
			str = runMatcher.ReplaceAllString(str, "RUN \\0")

			return str
		},
	}
)

// replaceJSONInput takes a gjson path and replaces all elements the path matches with the output of matcher
func replaceJSONInput(t *testing.T, jsonInput, path string, matcher func(toReplace gjson.Result) any) string {
	t.Helper()

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
	t.Helper()

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
		for i2 := range int(structure.Int()) {
			newPath := strings.Replace(path, "#", strconv.Itoa(i2), 1)
			*pathToBuild = append(*pathToBuild, newPath)
		}
	}
}
