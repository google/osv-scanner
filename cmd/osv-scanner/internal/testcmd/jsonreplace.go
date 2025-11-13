package testcmd

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
	// OnlyIDVulnsRule simplifies vulnerabilities to only their ID
	OnlyIDVulnsRule = JSONReplaceRule{
		Path: "results.#.packages.#.vulnerabilities",
		ReplaceFunc: func(toReplace gjson.Result) any {
			return toReplace.Get("#.id").Value()
		},
	}
	// GroupsAsArrayLen replaces the groups array with its length
	GroupsAsArrayLen = JSONReplaceRule{
		Path: "results.#.packages.#.groups",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if toReplace.IsArray() {
				return len(toReplace.Array())
			}

			return 0
		},
	}
	// OnlyFirstBaseImage simplifies the array of base images to only the first one
	OnlyFirstBaseImage = JSONReplaceRule{
		Path: "image_metadata.base_images.#",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if toReplace.IsArray() && len(toReplace.Array()) >= 1 {
				return toReplace.Array()[0].Value()
			}

			return struct{}{}
		},
	}
	// AnyDiffID truncates diff ids in image layer metadata to just `sha256:...`
	AnyDiffID = JSONReplaceRule{
		Path: "image_metadata.layer_metadata.#.diff_id",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if len(toReplace.String()) > 7 {
				return toReplace.String()[:7] + "..."
			}

			return ""
		},
	}
	// ShortenHistoryCommandLength truncates COMMAND data to 28 characters
	ShortenHistoryCommandLength = JSONReplaceRule{
		Path: "image_metadata.layer_metadata.#.command",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if len(toReplace.String()) > 28 {
				return toReplace.String()[:25] + "..."
			}

			return toReplace.String()
		},
	}
	// NormalizeHistoryCommand replaces COMMAND data to be consistent
	// across different versions of docker
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

	// NormalizeCreateDateSPDX replaces the created date with a placeholder date
	NormalizeCreateDateSPDX = JSONReplaceRule{
		Path: "creationInfo.created",
		ReplaceFunc: func(_ gjson.Result) any {
			return "2025-01-01T01:01:01Z"
		},
	}
)

func expandArrayPaths(t *testing.T, jsonInput string, path string) []string {
	t.Helper()

	// split on the first intermediate #, if present
	pathToArray, restOfPath, hasArrayPlaceholder := strings.Cut(path, ".#.")

	// if there is no intermediate placeholder, check for (and cut) a terminal one
	if !hasArrayPlaceholder {
		pathToArray, hasArrayPlaceholder = strings.CutSuffix(path, ".#")
	}

	// if there are no array placeholders in the path, just return it
	if !hasArrayPlaceholder {
		return []string{path}
	}

	r := gjson.Get(jsonInput, pathToArray)

	// skip properties that are not arrays
	if !r.IsArray() {
		return []string{}
	}

	// if property exists and is actually an array, build out the path to each item
	// within that array
	paths := make([]string, 0, len(r.Array()))

	for i := range r.Array() {
		static := pathToArray + "." + strconv.Itoa(i)

		if restOfPath != "" {
			static += "." + restOfPath
		}
		paths = append(paths, expandArrayPaths(t, jsonInput, static)...)
	}

	return paths
}

// replaceJSONInput takes a gjson path and replaces all elements the path matches with the output of matcher
func replaceJSONInput(t *testing.T, jsonInput string, path string, replacer func(toReplace gjson.Result) any) string {
	t.Helper()

	var err error
	json := jsonInput
	for _, pathElem := range expandArrayPaths(t, jsonInput, path) {
		res := gjson.Get(jsonInput, pathElem)

		if !res.Exists() {
			continue
		}

		// optimistically replace the element, since we know at this point it does exist
		json, err = sjson.SetOptions(json, pathElem, replacer(res), &sjson.Options{Optimistic: true})
		if err != nil {
			t.Fatalf("failed to set element")
		}
	}

	return json
}
