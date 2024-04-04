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

// Package schema provides mechanisms for describing ecosystems that can be used
// to construct a resolve.LocalClient or a resolve.Graph suitable for use in
// tests.
package schema

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/resolve/version"
	"github.com/google/osv-scanner/internal/resolution/clienttest/tmp/deptest"
	"github.com/google/osv-scanner/internal/resolution/clienttest/tmp/versiontest"
)

/*
Schema represents an ecosystem of packages, versions, and imports.

A Schema may be declared using a simple, tab-sensitive grammar, with each level
of indentation representing the declaration of a package, version, import, and
attributes:

	# Comment
	Name [RefreshTime as YYYY-MM-DD]
		[VersionAttr|]Version
			ATTR: AttrKey AttrVal
			[DepType|]Name@RequirementVersion
			[DepType|]Name@ConcreteVersion
		SymbolicVersion -> ConcreteVersion

[VersionAttr|] is optional and defines the version attributes.
An alternate way to add an attribute is to add lines, indented under the
version, starting with "ATTR:" and defining an AttrKey and an AttrVal.

[DepType|] is optional and defines the dependency type. Attribute keys and
values are space-separated.

See the "schema" example for a sample schema.
*/
type Schema struct {
	Packages []Package
}

// Package returns the Package for the package with the given name, or nil
// if none exists in the schema.
func (s Schema) Package(name string) *Package {
	_, name = parseName(name)
	for i := range s.Packages {
		if s.Packages[i].Name == name {
			return &s.Packages[i]
		}
	}
	return nil
}

// Package represents a package in a schema.
type Package struct {
	resolve.PackageKey
	Versions []Version
}

// Version returns the Version for the version with the given version and
// type, or nil if none exists in the schema.
func (s *Package) Version(version string, vt resolve.VersionType) *Version {
	want := resolve.VersionKey{
		PackageKey:  s.PackageKey,
		VersionType: vt,
		Version:     version,
	}
	for i := range s.Versions {
		if s.Versions[i].VersionKey == want {
			return &s.Versions[i]
		}
	}
	return nil
}

// Version represents a version in a schema.
type Version struct {
	resolve.VersionKey
	Attr         version.AttrSet
	Requirements []resolve.RequirementVersion // For concrete versions.
}

func sortRequirements(s []resolve.RequirementVersion) {
	sort.Slice(s, func(i, j int) bool {
		if x := s[i].Type.Compare(s[j].Type); x != 0 {
			return x < 0
		}
		return s[i].VersionKey.Less(s[j].VersionKey)
	})
}

// New parses a textual representation of a Schema and returns it.
// The given System is used for all packages in the schema.
func New(text string, sys resolve.System) (*Schema, error) {
	var (
		schema Schema
		p      *Package
		ver    *Version
		imp    *resolve.RequirementVersion
	)
	impDone := func() {
		if imp != nil {
			ver.Requirements = append(ver.Requirements, *imp)
			imp = nil
		}
	}
	verDone := func() {
		impDone()
		if ver != nil {
			p.Versions = append(p.Versions, *ver)
			ver = nil
		}
	}
	packageDone := func() {
		verDone()
		if p != nil {
			schema.Packages = append(schema.Packages, *p)
			p = nil
		}
	}

	for i, line := range strings.Split(text, "\n") {
		// Trim comments that begin with #.
		if j := strings.Index(line, "#"); j >= 0 {
			line = line[:j]
		}
		// Remove trailing spaces.
		line = strings.TrimRightFunc(line, unicode.IsSpace)
		// Ignore lines that contain only spaces.
		if line == "" {
			continue
		}
		// Count and trim leading tabs.
		tabs := 0
		for line[tabs] == '\t' {
			tabs++
		}
		line = line[tabs:]
		// Error on leading space.
		if line[0] == ' ' {
			return nil, fmt.Errorf("line %d has leading space where tabs are expected", i)
		}

		switch tabs {
		case 0:
			packageDone()

			var name string
			switch fields := strings.Fields(line); len(fields) {
			case 1:
				name = fields[0]
			default:
				return nil, fmt.Errorf("too many fields in line %q", line)
			}

			_, name = parseName(name)
			p = &Package{
				PackageKey: resolve.PackageKey{
					System: sys,
					Name:   name,
				},
			}

		case 1:
			if p == nil {
				return nil, fmt.Errorf("version %q before package", line)
			}
			verDone()

			ver = &Version{}
			ver.PackageKey = p.PackageKey

			ver.Attr, ver.Version = parseVersionName(line)
			ver.Version = strings.TrimSpace(ver.Version)
			ver.VersionType = resolve.Concrete

		case 2:
			if p == nil {
				return nil, fmt.Errorf("import %q before package", line)
			}
			if ver == nil {
				return nil, fmt.Errorf("import %q before version", line)
			}
			impDone()

			if strings.HasPrefix(line, "ATTR:") {
				attr, err := versiontest.ParseSingle(line[5:])
				if err != nil {
					return nil, fmt.Errorf("cannot parse attribute: %w", err)
				}
				attr.ForEachAttr(func(key version.AttrKey, value string) {
					ver.Attr.SetAttr(key, value)
				})
				break
			}

			imp = &resolve.RequirementVersion{}
			imp.System = p.System

			parts := strings.SplitN(line, "@", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf(`got import %q, expect "package@version"`, line)
			}

			imp.Type, imp.Name = parseName(parts[0])
			imp.Version = parts[1]
			imp.VersionType = resolve.Requirement

		default:
			return nil, fmt.Errorf("line %d begins with %d tabs, which is too many", i, tabs)
		}
	}
	packageDone()

	return &schema, nil
}

// NewClient returns a resolve.Client that returns all of the packages and versions
// defined in the Schema.
func (s Schema) NewClient() *resolve.LocalClient {
	client := resolve.NewLocalClient()
	for _, p := range s.Packages {
		for _, v := range p.Versions {
			resolve.SortDependencies(v.Requirements)
			client.AddVersion(resolve.Version{
				VersionKey: v.VersionKey,
				AttrSet:    v.Attr,
			}, v.Requirements)
		}
	}
	return client
}

// ValidateClient checks that the given resolve.LocalClient holds all the
// elements of the Schema.
func (s Schema) ValidateClient(client *resolve.LocalClient) error {
	ctx := context.Background()
	var (
		wantPackages     = map[resolve.PackageKey]bool{}
		wantVersions     = map[resolve.PackageKey][]resolve.Version{}
		wantRequirements = map[resolve.VersionKey][]resolve.RequirementVersion{}
	)
	for _, p := range s.Packages {
		pk := p.PackageKey
		for _, ver := range p.Versions {
			wantPackages[pk] = true
			wantVersions[pk] = append(wantVersions[pk], resolve.Version{
				VersionKey: ver.VersionKey,
				AttrSet:    ver.Attr,
			})

			switch ver.VersionType {
			default:
				panic(fmt.Errorf("unexpected version type in schema: %v", ver))

			case resolve.Concrete:
				wantRequirements[ver.VersionKey] = append(wantRequirements[ver.VersionKey], ver.Requirements...)
				for _, imp := range ver.Requirements {
					ivk := imp.VersionKey
					ipk := ivk.PackageKey
					wantPackages[ipk] = true
				}
			}
		}
	}
	gotPackages := map[resolve.PackageKey]bool{}
	for pk := range client.PackageVersions {
		gotPackages[pk] = true
	}
	if !reflect.DeepEqual(gotPackages, wantPackages) {
		return fmt.Errorf("LocalClient has packages\n\t:%v\nwant:\n\t%v", gotPackages, wantPackages)
	}
	for pk, want := range wantVersions {
		got, err := client.Versions(ctx, pk)
		if err != nil {
			return err
		}
		resolve.SortVersions(got)
		resolve.SortVersions(want)
		// Remove duplicates, which may arise from multiple similar
		// import statements.
		for i := 1; i < len(want); {
			if want[i-1].VersionKey == want[i].VersionKey {
				want = append(want[:i], want[i+1:]...)
				continue
			}
			i++
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("%v has versions:\n\t%v\nwant:\n\t%v", pk, got, want)
		}
	}
	for vk, want := range wantRequirements {
		got, err := client.Requirements(ctx, vk)
		if err != nil {
			return err
		}
		sortRequirements(got)
		sortRequirements(want)
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("%v imports:\n\t%v\nwant:\n\t%v", vk, got, want)
		}
	}
	return nil
}

func parseName(s string) (dt dep.Type, name string) {
	switch items := strings.Split(s, "|"); len(items) {
	case 2:
		dt, _ := deptest.ParseString(items[0])
		return dt, items[1]
	default:
		return dep.Type{}, s
	}
}

func parseVersionName(s string) (attr version.AttrSet, name string) {
	switch items := strings.Split(s, "|"); len(items) {
	case 2:
		attr, err := versiontest.ParseString(items[0])
		if err != nil {
			attr = version.AttrSet{}
		}
		return attr, items[1]
	default:
		return version.AttrSet{}, s
	}
}
