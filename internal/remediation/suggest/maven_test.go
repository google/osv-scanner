package suggest

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/resolution/manifest"
)

var (
	depMgmt           = depTypeWithOrigin("management")
	depParent         = depTypeWithOrigin("parent")
	depPlugin         = depTypeWithOrigin("plugin@org.plugin:plugin")
	depProfileOne     = depTypeWithOrigin("profile@profile-one")
	depProfileTwoMgmt = depTypeWithOrigin("profile@profile-two@management")
)

func depTypeWithOrigin(origin string) dep.Type {
	var result dep.Type
	result.AddAttr(dep.MavenDependencyOrigin, origin)

	return result
}

func mavenReqKey(t *testing.T, name, artifactType, classifier string) manifest.RequirementKey {
	t.Helper()
	var typ dep.Type
	if artifactType != "" {
		typ.AddAttr(dep.MavenArtifactType, artifactType)
	}
	if classifier != "" {
		typ.AddAttr(dep.MavenClassifier, classifier)
	}

	return manifest.MakeRequirementKey(resolve.RequirementVersion{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				Name:   name,
				System: resolve.Maven,
			},
		},
		Type: typ,
	})
}

func TestSuggest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := resolve.NewLocalClient()
	addVersions := func(sys resolve.System, name string, versions []string) {
		for _, version := range versions {
			client.AddVersion(resolve.Version{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: sys,
						Name:   name,
					},
					VersionType: resolve.Concrete,
					Version:     version,
				}}, nil)
		}
	}
	addVersions(resolve.Maven, "com.mycompany.app:parent-pom", []string{"1.0.0"})
	addVersions(resolve.Maven, "junit:junit", []string{"4.11", "4.12", "4.13", "4.13.2"})
	addVersions(resolve.Maven, "org.example:abc", []string{"1.0.0", "1.0.1", "1.0.2"})
	addVersions(resolve.Maven, "org.example:no-updates", []string{"9.9.9", "10.0.0"})
	addVersions(resolve.Maven, "org.example:property", []string{"1.0.0", "1.0.1"})
	addVersions(resolve.Maven, "org.example:same-property", []string{"1.0.0", "1.0.1"})
	addVersions(resolve.Maven, "org.example:another-property", []string{"1.0.0", "1.1.0"})
	addVersions(resolve.Maven, "org.example:property-no-update", []string{"1.9.0", "2.0.0"})
	addVersions(resolve.Maven, "org.example:xyz", []string{"2.0.0", "2.0.1"})
	addVersions(resolve.Maven, "org.profile:abc", []string{"1.2.3", "1.2.4"})
	addVersions(resolve.Maven, "org.profile:def", []string{"2.3.4", "2.3.5"})
	addVersions(resolve.Maven, "org.import:xyz", []string{"6.6.6", "6.7.0", "7.0.0"})
	addVersions(resolve.Maven, "org.dep:plugin-dep", []string{"2.3.1", "2.3.2", "2.3.3", "2.3.4"})

	suggester, err := GetSuggester(resolve.Maven)
	if err != nil {
		t.Fatalf("failed to get Maven suggester: %v", err)
	}

	depProfileTwoMgmt.AddAttr(dep.MavenArtifactType, "pom")
	depProfileTwoMgmt.AddAttr(dep.Scope, "import")

	mf := manifest.Manifest{
		FilePath: filepath.Join("fixtures", "pom.xml"),
		Root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "com.mycompany.app:my-app",
				},
				VersionType: resolve.Concrete,
				Version:     "1.0.0",
			},
		},
		Requirements: []resolve.RequirementVersion{
			{
				// Test dependencies are not updated.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "junit:junit",
					},
					VersionType: resolve.Requirement,
					Version:     "4.12",
				},
				Type: dep.NewType(dep.Test),
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:abc",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.1",
				},
			},
			{
				// A package is specified to disallow updates.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:no-updates",
					},
					VersionType: resolve.Requirement,
					Version:     "9.9.9",
				},
			},
			{
				// The universal property should be updated.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:property",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.0",
				},
			},
			{
				// Property cannot be updated, so update the dependency directly.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:property-no-update",
					},
					VersionType: resolve.Requirement,
					Version:     "1.9",
				},
			},
			{
				// The property is updated to the same value.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:same-property",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.0",
				},
			},
			{
				// Property needs to be updated to a different value,
				// so update dependency directly.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:another-property",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.0",
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:xyz",
					},
					VersionType: resolve.Requirement,
					Version:     "2.0.0",
				},
				Type: depMgmt,
			},
		},
		Groups: map[manifest.RequirementKey][]string{
			mavenReqKey(t, "junit:junit", "", ""):    {"test"},
			mavenReqKey(t, "org.import:xyz", "", ""): {"import"},
		},
		EcosystemSpecific: manifest.MavenManifestSpecific{
			RequirementsForUpdates: []resolve.RequirementVersion{
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "com.mycompany.app:parent-pom",
						},
						VersionType: resolve.Requirement,
						Version:     "1.0.0",
					},
					Type: depParent,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.profile:abc",
						},
						VersionType: resolve.Requirement,
						Version:     "1.2.3",
					},
					Type: depProfileOne,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.profile:def",
						},
						VersionType: resolve.Requirement,
						Version:     "2.3.4",
					},
					Type: depProfileOne,
				},
				{
					// A package is specified to ignore major updates.
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.import:xyz",
						},
						VersionType: resolve.Requirement,
						Version:     "6.6.6",
					},
					Type: depProfileTwoMgmt,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.dep:plugin-dep",
						},
						VersionType: resolve.Requirement,
						Version:     "2.3.3",
					},
					Type: depPlugin,
				},
			},
		},
	}

	got, err := suggester.Suggest(ctx, client, mf, Options{
		IgnoreDev:  true, // Do no update test dependencies.
		NoUpdates:  []string{"org.example:no-updates"},
		AvoidMajor: []string{"org.import:xyz"},
	})
	if err != nil {
		t.Fatalf("failed to suggest ManifestPatch: %v", err)
	}

	want := manifest.ManifestPatch{
		Deps: []manifest.DependencyPatch{
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.dep:plugin-dep",
				},
				Type:       depPlugin,
				NewRequire: "2.3.4",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.example:abc",
				},
				NewRequire: "1.0.2",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.example:another-property",
				},
				NewRequire: "1.1.0",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.example:property",
				},
				NewRequire: "1.0.1",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.example:property-no-update",
				},
				NewRequire: "2.0.0",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.example:same-property",
				},
				NewRequire: "1.0.1",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.example:xyz",
				},
				Type:       depMgmt,
				NewRequire: "2.0.1",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.import:xyz",
				},
				Type:       depProfileTwoMgmt,
				NewRequire: "6.7.0",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.profile:abc",
				},
				Type:       depProfileOne,
				NewRequire: "1.2.4",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.profile:def",
				},
				Type:       depProfileOne,
				NewRequire: "2.3.5",
			},
		},
		EcosystemSpecific: manifest.MavenManifestSpecific{
			// Copied from Manifest.EcosystemSpecific
			RequirementsForUpdates: []resolve.RequirementVersion{
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "com.mycompany.app:parent-pom",
						},
						VersionType: resolve.Requirement,
						Version:     "1.0.0",
					},
					Type: depParent,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.profile:abc",
						},
						VersionType: resolve.Requirement,
						Version:     "1.2.3",
					},
					Type: depProfileOne,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.profile:def",
						},
						VersionType: resolve.Requirement,
						Version:     "2.3.4",
					},
					Type: depProfileOne,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.import:xyz",
						},
						VersionType: resolve.Requirement,
						Version:     "6.6.6",
					},
					Type: depProfileTwoMgmt,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.dep:plugin-dep",
						},
						VersionType: resolve.Requirement,
						Version:     "2.3.3",
					},
					Type: depPlugin,
				},
			},
		},
	}
	sort.Slice(got.Deps, func(i, j int) bool {
		return got.Deps[i].Pkg.Name < got.Deps[j].Pkg.Name
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ManifestPatch suggested does not match expected: got %v\n want %v", got, want)
	}
}

func TestSuggestVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lc := resolve.NewLocalClient()

	pk := resolve.PackageKey{
		System: resolve.Maven,
		Name:   "abc:xyz",
	}
	for _, version := range []string{"1.0.0", "1.0.1", "1.1.0", "1.2.3", "2.0.0", "2.2.2", "2.3.4"} {
		lc.AddVersion(resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Concrete,
				Version:     version,
			}}, nil)
	}

	tests := []struct {
		requirement    string
		noMajorUpdates bool
		want           string
	}{
		{"1.0.0", false, "2.3.4"},
		// No major updates allowed
		{"1.0.0", true, "1.2.3"},
		// Version range requirement is not outdated
		{"[1.0.0,)", false, "[1.0.0,)"},
		{"[2.0.0, 2.3.4]", false, "[2.0.0, 2.3.4]"},
		// Version range requirement is outdated
		{"[2.0.0, 2.3.4)", false, "2.3.4"},
		{"[2.0.0, 2.2.2]", false, "2.3.4"},
		// Version range requirement is outdated but latest version is a major update
		{"[1.0.0,2.0.0)", false, "2.3.4"},
		{"[1.0.0,2.0.0)", true, "[1.0.0,2.0.0)"},
	}
	for _, test := range tests {
		vk := resolve.VersionKey{
			PackageKey:  pk,
			VersionType: resolve.Requirement,
			Version:     test.requirement,
		}
		want := resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Requirement,
				Version:     test.want,
			},
		}
		got, err := suggestMavenVersion(ctx, lc, resolve.RequirementVersion{VersionKey: vk}, test.noMajorUpdates)
		if err != nil {
			t.Fatalf("fail to suggest a new version for %v: %v", vk, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("suggestMavenVersion(%v, %t): got %s want %s", vk, test.noMajorUpdates, got, want)
		}
	}
}
