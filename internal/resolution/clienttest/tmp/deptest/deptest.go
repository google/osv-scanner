// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package deptest contains helpers to aid testing code that interacts with dependency types.
*/
package deptest

import (
	"fmt"
	"strconv"
	"strings"

	"deps.dev/util/resolve/dep"
)

var (
	// allKeys lists all available attribute keys.
	allKeys = []dep.AttrKey{
		dep.Dev,
		dep.Opt,
		dep.Test,
		dep.XTest,
		dep.Framework,
		dep.Scope,
		dep.MavenClassifier,
		dep.MavenArtifactType,
		dep.MavenDependencyOrigin,
		dep.MavenExclusions,
		dep.EnabledDependencies,
		dep.KnownAs,
		dep.Environment,
		dep.Selector,
	}
	// flagKeys holds the keys that have no value by design.
	flagKeys = map[dep.AttrKey]bool{
		dep.Dev:      true,
		dep.Opt:      true,
		dep.Test:     true,
		dep.Selector: true,
	}
	// parsingDict holds a parsing dictionary that maps string tokens to
	// their corresponding attribute key. The string token is taken as the
	// lowercase string representation of the attribute key.
	parsingDict = buildParsingDict(allKeys)
)

// buildParsingDict returns a dictionary that maps the lowercase string
// representation of each key from the given key list to itself.
func buildParsingDict(keys []dep.AttrKey) map[string]dep.AttrKey {
	d := make(map[string]dep.AttrKey, len(keys))
	for _, k := range keys {
		d[strings.ToLower(k.String())] = k
	}
	return d
}

// Parse parses the given string and returns the corresponding dependency type.
// Keys and attributes are space separated.
// Examples:
//
//	Opt
//	Opt Dev
//	Framework .NETStandard1.0
//	Dev Framework .NETStandard1.0 Test
func ParseString(s string) (dep.Type, error) {
	var dt dep.Type
	items := strings.Fields(s)
	// Join quoted fields back together.
	var (
		quoted []string
		w      int
	)
	for i := 0; i < len(items); i++ {
		if items[i][0] != '"' {
			items[w] = items[i]
			w++
			continue
		}
		for i < len(items) {
			s := items[i]
			quoted = append(quoted, s)
			i++
			if s[len(s)-1] == '"' {
				if len(s) >= 2 && s[len(s)-2:] == `\"` {
					continue
				}
				uq, err := strconv.Unquote(strings.Join(quoted, " "))
				if err != nil {
					return dep.Type{}, err
				}
				items[w] = uq
				w++
				quoted = quoted[:0]
				break
			}
		}
	}
	if len(quoted) != 0 {
		return dep.Type{}, fmt.Errorf("unterminated quotes in %s", s)
	}
	items = items[:w]
	for i := 0; i < len(items); i++ {
		key, ok := parsingDict[strings.ToLower(items[i])]
		if !ok {
			return dep.Type{}, fmt.Errorf("unexpected key (%q)", items[i])
		}
		if flagKeys[key] {
			dt.AddAttr(key, "")
			continue
		}
		if i == len(items)-1 {
			return dep.Type{}, fmt.Errorf("missing value for %s", key)
		}
		i++
		dt.AddAttr(key, items[i])
	}
	return dt, nil
}

// Must returns the given dep type if the given error is nil, otherwise panics.
func Must(dt dep.Type, err error) dep.Type {
	if err != nil {
		panic(err)
	}
	return dt
}
