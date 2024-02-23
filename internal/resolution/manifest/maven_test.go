package manifest

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/lockfile"
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

func TestMavenRead(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	df, err := lockfile.OpenLocalDepFile(filepath.Join(dir, "fixtures", "pom.xml"))
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}

	mavenIO := MavenManifestIO{}
	got, err := mavenIO.Read(df)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.HasSuffix(got.FilePath, "pom.xml") {
		t.Errorf("manifest file path %v does not have pom.xml", got.FilePath)
	}
	got.FilePath = ""

	depProfileTwoMgmt.AddAttr(dep.MavenArtifactType, "pom")
	depProfileTwoMgmt.AddAttr(dep.Scope, "import")

	want := Manifest{
		Root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "com.mycompany.app:my-app",
				},
				VersionType: resolve.Concrete,
				Version:     "1.0",
			},
		},
		Requirements: []resolve.RequirementVersion{
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.parent:parent-pom",
					},
					VersionType: resolve.Requirement,
					Version:     "1.1.1",
				},
				Type: depParent,
			},
			{
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
					Version:     "${def.version}",
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
		Groups: map[resolve.PackageKey][]string{
			{System: resolve.Maven, Name: "junit:junit"}:    {"test"},
			{System: resolve.Maven, Name: "org.import:xyz"}: {"import"},
		},
		EcosystemSpecific: MavenManifestSpecific{
			Properties: []PropertyWithOrigin{
				{Property: maven.Property{Name: "project.build.sourceEncoding", Value: "UTF-8"}},
				{Property: maven.Property{Name: "maven.compiler.source", Value: "1.7"}},
				{Property: maven.Property{Name: "maven.compiler.target", Value: "1.7"}},
				{Property: maven.Property{Name: "junit.version", Value: "4.12"}},
				{Property: maven.Property{Name: "def.version", Value: "2.3.4"}, Origin: "profile@profile-one"},
			},
			OriginalImports: []resolve.RequirementVersion{
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "junit:junit",
						},
						VersionType: resolve.Requirement,
						Version:     "${junit.version}",
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
						Version:     "${def.version}",
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
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Maven manifest mismatch:\ngot %v\nwant %v\n", got, want)
	}
}

func TestMavenWrite(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	df, err := lockfile.OpenLocalDepFile(filepath.Join(dir, "fixtures", "pom.xml"))
	if err != nil {
		t.Fatalf("fail to open file: %v", err)
	}

	depProfileTwoMgmt.AddAttr(dep.MavenArtifactType, "pom")
	depProfileTwoMgmt.AddAttr(dep.Scope, "import")

	changes := ManifestPatch{
		Deps: []DependencyPatch{
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
					Name:   "org.example:xyz",
				},
				Type:       depMgmt,
				NewRequire: "2.0.1",
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
					Name:   "org.import:xyz",
				},
				Type:       depProfileTwoMgmt,
				NewRequire: "7.0.0",
			},
			{
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.dep:plugin-dep",
				},
				Type:       depPlugin,
				NewRequire: "2.3.4",
			}, {
				Pkg: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.parent:parent-pom",
				},
				Type:       depParent,
				NewRequire: "1.2.0",
			},
		},
		EcosystemSpecific: MavenPropertyPatches{
			"": {
				"junit.version": "4.13.2",
			},
			"profile@profile-one": {
				"def.version": "2.3.5",
			},
		},
	}

	buf := new(bytes.Buffer)
	mavenIO := MavenManifestIO{}
	if err := mavenIO.Write(df, buf, changes); err != nil {
		t.Fatalf("unable to update Maven pom.xml: %v", err)
	}
	testutility.NewSnapshot().WithWindowsReplacements(map[string]string{"\r\n": "\n"}).MatchText(t, buf.String())
}
