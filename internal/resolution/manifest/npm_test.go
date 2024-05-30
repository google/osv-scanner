package manifest_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/lockfile"
)

func aliasType(t *testing.T, aliasedName string) dep.Type {
	t.Helper()
	var typ dep.Type
	typ.AddAttr(dep.KnownAs, aliasedName)

	return typ
}

func npmVK(t *testing.T, name, version string, versionType resolve.VersionType) resolve.VersionKey {
	t.Helper()
	return resolve.VersionKey{
		PackageKey: resolve.PackageKey{
			System: resolve.NPM,
			Name:   name,
		},
		Version:     version,
		VersionType: versionType,
	}
}

func npmReqKey(t *testing.T, name, knownAs string) manifest.RequirementKey {
	t.Helper()
	var typ dep.Type
	if knownAs != "" {
		typ.AddAttr(dep.KnownAs, knownAs)
	}

	return manifest.MakeRequirementKey(resolve.RequirementVersion{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				Name:   name,
				System: resolve.NPM,
			},
		},
		Type: typ,
	})
}

func TestNpmRead(t *testing.T) {
	t.Parallel()

	df, err := lockfile.OpenLocalDepFile("./fixtures/package.json")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer df.Close()

	npmIO := manifest.NpmManifestIO{}
	got, err := npmIO.Read(df)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.HasSuffix(got.FilePath, "package.json") {
		t.Errorf("manifest file path %v does not have package.json", got.FilePath)
	}
	got.FilePath = ""

	want := manifest.Manifest{
		Root: resolve.Version{
			VersionKey: npmVK(t, "npm-manifest", "1.0.0", resolve.Concrete),
		},
		// npm dependencies should resolve in alphabetical order, regardless of type
		Requirements: []resolve.RequirementVersion{
			// TODO: @babel/core peerDependency currently not resolved
			{
				Type:       aliasType(t, "cliui"), // sorts on aliased name, not real package name
				VersionKey: npmVK(t, "@isaacs/cliui", "^8.0.2", resolve.Requirement),
			},
			{
				// Type: dep.NewType(dep.Dev), devDependencies treated as prod to make resolution work
				VersionKey: npmVK(t, "eslint", "^8.57.0", resolve.Requirement),
			},
			{
				Type:       dep.NewType(dep.Opt),
				VersionKey: npmVK(t, "glob", "^10.3.10", resolve.Requirement),
			},
			{
				VersionKey: npmVK(t, "jquery", "latest", resolve.Requirement),
			},
			{
				VersionKey: npmVK(t, "lodash", "4.17.17", resolve.Requirement),
			},
			{
				VersionKey: npmVK(t, "string-width", "^5.1.2", resolve.Requirement),
			},
			{
				Type:       aliasType(t, "string-width-aliased"),
				VersionKey: npmVK(t, "string-width", "^4.2.3", resolve.Requirement),
			},
		},
		Groups: map[manifest.RequirementKey][]string{
			npmReqKey(t, "eslint", ""): {"dev"},
			npmReqKey(t, "glob", ""):   {"optional"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("npm manifest mismatch:\ngot %v\nwant %v\n", got, want)
	}
}

func TestNpmWorkspaceRead(t *testing.T) {
	t.Parallel()

	df, err := lockfile.OpenLocalDepFile("./fixtures/npm-workspaces/package.json")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer df.Close()

	npmIO := manifest.NpmManifestIO{}
	got, err := npmIO.Read(df)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.HasSuffix(got.FilePath, "package.json") {
		t.Errorf("manifest file path %v does not have package.json", got.FilePath)
	}
	got.FilePath = ""
	for i, local := range got.LocalManifests {
		if !strings.HasSuffix(local.FilePath, "package.json") {
			t.Errorf("local manifest file path %v does not have package.json", local.FilePath)
		}
		got.LocalManifests[i].FilePath = ""
	}

	want := manifest.Manifest{
		Root: resolve.Version{
			VersionKey: npmVK(t, "npm-workspace-test", "1.0.0", resolve.Concrete),
		},
		Requirements: []resolve.RequirementVersion{
			// root dependencies always before workspace
			{
				Type:       aliasType(t, "jquery-real"),
				VersionKey: npmVK(t, "jquery", "^3.7.1", resolve.Requirement),
			},
			// workspaces in path order
			{
				VersionKey: npmVK(t, "jquery:workspace", "^3.7.1", resolve.Requirement),
			},
			{
				VersionKey: npmVK(t, "@workspace/ugh:workspace", "*", resolve.Requirement),
			},
			{
				VersionKey: npmVK(t, "z-z-z:workspace", "*", resolve.Requirement),
			},
		},
		Groups: map[manifest.RequirementKey][]string{
			npmReqKey(t, "jquery", "jquery-real"): {"dev"},
			// excludes workspace dev dependency
		},
		LocalManifests: []manifest.Manifest{
			{
				Root: resolve.Version{
					VersionKey: npmVK(t, "jquery:workspace", "3.7.1", resolve.Concrete),
				},
				Requirements: []resolve.RequirementVersion{
					{
						VersionKey: npmVK(t, "semver", "^7.6.0", resolve.Requirement),
					},
				},
				Groups: map[manifest.RequirementKey][]string{},
			},
			{
				Root: resolve.Version{
					VersionKey: npmVK(t, "@workspace/ugh:workspace", "0.0.1", resolve.Concrete),
				},
				Requirements: []resolve.RequirementVersion{
					{
						VersionKey: npmVK(t, "jquery:workspace", "*", resolve.Requirement),
					},
					{
						VersionKey: npmVK(t, "semver", "^6.3.1", resolve.Requirement),
					},
				},
				Groups: map[manifest.RequirementKey][]string{
					npmReqKey(t, "jquery:workspace", ""): {"dev"},
					npmReqKey(t, "semver", ""):           {"dev"},
				},
			},
			{
				Root: resolve.Version{
					VersionKey: npmVK(t, "z-z-z:workspace", "1.0.0", resolve.Concrete),
				},
				Requirements: []resolve.RequirementVersion{
					{
						VersionKey: npmVK(t, "@workspace/ugh:workspace", "*", resolve.Requirement),
					},
					{
						VersionKey: npmVK(t, "semver", "^5.7.2", resolve.Requirement),
					},
				},
				Groups: map[manifest.RequirementKey][]string{},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("npm manifest mismatch:\ngot  %v\nwant %v\n", got, want)
	}
}

func TestNpmWrite(t *testing.T) {
	t.Parallel()

	df, err := lockfile.OpenLocalDepFile("./fixtures/package.json")
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer df.Close()

	changes := manifest.ManifestPatch{
		Deps: []manifest.DependencyPatch{
			{
				Pkg: resolve.PackageKey{
					System: resolve.NPM,
					Name:   "lodash",
				},
				OrigRequire: "4.17.17",
				NewRequire:  "^4.17.21",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.NPM,
					Name:   "eslint",
				},
				OrigRequire: "^8.57.0",
				NewRequire:  "*",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.NPM,
					Name:   "glob",
				},
				OrigRequire: "^10.3.10",
				NewRequire:  "^1.0.0",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.NPM,
					Name:   "jquery",
				},
				OrigRequire: "latest",
				NewRequire:  "~0.0.1",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.NPM,
					Name:   "@isaacs/cliui",
				},
				Type:        aliasType(t, "cliui"),
				OrigRequire: "^8.0.2",
				NewRequire:  "^9.0.0",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.NPM,
					Name:   "string-width",
				},
				OrigRequire: "^5.1.2",
				NewRequire:  "^7.1.0",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.NPM,
					Name:   "string-width",
				},
				Type:        aliasType(t, "string-width-aliased"),
				OrigRequire: "^4.2.3",
				NewRequire:  "^6.1.0",
			},
		},
	}

	buf := new(bytes.Buffer)
	npmIO := manifest.NpmManifestIO{}
	if err := npmIO.Write(df, buf, changes); err != nil {
		t.Fatalf("unable to update npm package.json: %v", err)
	}
	testutility.NewSnapshot().WithCRLFReplacement().MatchText(t, buf.String())
}
