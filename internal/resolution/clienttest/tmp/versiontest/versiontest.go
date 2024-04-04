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
Package versiontest contains helpers to aid testing code that interacts with
version attributes.
*/
package versiontest

import (
	"fmt"
	"strconv"
	"strings"

	"deps.dev/util/resolve/version"
)

var (
	// allKeys lists all available version keys.
	allKeys = []version.AttrKey{
		version.Blocked,
		version.Deleted,
		version.Error,
		version.Redirect,
		version.Features,
		version.DerivedFrom,
		version.NativeLibrary,
		version.Registries,
		version.SupportedFrameworks,
		version.DependencyGroups,
		version.Ident,
		version.Created,
		version.Tags,
	}
	// flagKeys holds the keys that have an empty value by design.
	flagKeys = map[version.AttrKey]bool{
		version.Blocked: true,
		version.Deleted: true,
		version.Error:   true,
	}

	parsingDict = buildParsingDict(allKeys)
)

// buildParsingDict returns a dictionary that maps the lowercase string
// representation of each key from the given key list to itself.
func buildParsingDict(keys []version.AttrKey) map[string]version.AttrKey {
	d := make(map[string]version.AttrKey, len(keys))
	for _, k := range keys {
		d[strings.ToLower(k.String())] = k
	}
	return d
}

// Parse parses the given string and returns the corresponding version
// attribute. Keys and values are space separated.
// Examples:
//
//	Bundle
//	Redirect name
//	Redirect name Bundle
func ParseString(s string) (version.AttrSet, error) {
	var attr version.AttrSet
	items := strings.Fields(s)
	for i := 0; i < len(items); i++ {
		key, ok := parsingDict[strings.ToLower(items[i])]
		if !ok {
			return version.AttrSet{}, fmt.Errorf("unexpected key (%q)", items[i])
		}
		if flagKeys[key] {
			attr.SetAttr(key, "")
			continue
		}
		if i == len(items)-1 {
			return version.AttrSet{}, fmt.Errorf("missing value for %s", key)
		}
		i++
		attr.SetAttr(key, items[i])
	}
	return attr, nil
}

// ParseSingle parses the given string and returns the corresponding version
// attribute composed of one key and its value. The key and the value are
// space separated. The key and the value of the version attribute are trimmed.
// Examples:
//
//	SomeKey some value until the end of the string
//	SomeKey "some quoted \"value\" with no trailing data"
//	SomeKey `a backtick "quoted" value`
func ParseSingle(s string) (version.AttrSet, error) {
	key, val, ok := strings.Cut(strings.TrimSpace(s), " ")
	if ok {
		val = strings.TrimSpace(val)
		if len(val) > 0 && (val[0] == '"' || val[0] == '`') {
			v, err := strconv.Unquote(val)
			if err != nil {
				return version.AttrSet{}, fmt.Errorf("bad quoted value %q for key %q", val, key)
			}
			val = v
		}
	}
	k, ok := parsingDict[strings.ToLower(key)]
	if !ok {
		return version.AttrSet{}, fmt.Errorf("unexpected key %q", key)
	}
	var attr version.AttrSet
	attr.SetAttr(k, val)
	return attr, nil
}

// String returns a string representation of the given type that is
// compatible with ParseString.
// For any given dt, dt.Equal(Must(ParseString(String(dt))))
func String(attr version.AttrSet) string {
	var ss []string
	for _, key := range allKeys {
		if value, ok := attr.GetAttr(key); ok {
			ss = append(ss, strings.ToLower(key.String()))
			if value != "" {
				ss = append(ss, value)
			}
		}
	}
	return strings.Join(ss, " ")
}
