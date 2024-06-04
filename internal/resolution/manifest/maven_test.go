package manifest_test

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
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/lockfile"
)

var (
	depImport             = depTypeWithOrigin("import@org.import:import@management")
	depMgmt               = depTypeWithOrigin("management")
	depParent             = depTypeWithOrigin("parent")
	depParentMgmt         = depTypeWithOrigin("parent@org.parent:parent-pom@management")
	depParentUpstreamMgmt = depTypeWithOrigin("parent@org.upstream:parent-pom@management")
	depPlugin             = depTypeWithOrigin("plugin@org.plugin:plugin")
	depProfileOne         = depTypeWithOrigin("profile@profile-one")
	depProfileTwoMgmt     = depTypeWithOrigin("profile@profile-two@management")
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

func TestMavenRead(t *testing.T) {
	t.Parallel()

	srv := testutility.NewMockHTTPServer(t)
	srv.SetResponse(t, "org/upstream/parent-pom/1.2.3/parent-pom-1.2.3.pom", []byte(`
	<project>
	  <groupId>org.upstream</groupId>
	  <artifactId>parent-pom</artifactId>
	  <version>1.2.3</version>
	  <packaging>pom</packaging>
	  <properties>
			<bbb.artifact>bbb</bbb.artifact>
		  <bbb.version>2.2.2</bbb.version>
	  </properties>
	  <dependencyManagement>
		<dependencies>
		  <dependency>
			<groupId>org.example</groupId>
			<artifactId>${bbb.artifact}</artifactId>
			<version>${bbb.version}</version>
		  </dependency>
		</dependencies>
	  </dependencyManagement>
	</project>
	`))
	srv.SetResponse(t, "org/import/import/1.0.0/import-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.import</groupId>
	  <artifactId>import</artifactId>
	  <version>1.0.0</version>
	  <packaging>pom</packaging>
	  <properties>
		  <ccc.version>3.3.3</ccc.version>
	  </properties>
	  <dependencyManagement>
		  <dependencies>
		    <dependency>
			    <groupId>org.example</groupId>
			    <artifactId>ccc</artifactId>
			    <version>${ccc.version}</version>
		    </dependency>
		  </dependencies>
	  </dependencyManagement>
	</project>
	`))

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	df, err := lockfile.OpenLocalDepFile(filepath.Join(dir, "fixtures", "pom.xml"))
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer df.Close()

	mavenIO := manifest.MavenManifestIO{
		MavenRegistryAPIClient: *datasource.NewMavenRegistryAPIClient(srv.URL),
	}

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

	want := manifest.Manifest{
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
				// Type: dep.NewType(dep.Test), test scope is ignored to make resolution work.
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
		Groups: map[manifest.RequirementKey][]string{
			mavenReqKey(t, "junit:junit", "", ""):       {"test"},
			mavenReqKey(t, "org.import:xyz", "pom", ""): {"import"},
		},
		EcosystemSpecific: manifest.MavenManifestSpecific{
			Properties: []manifest.PropertyWithOrigin{
				{Property: maven.Property{Name: "bbb.artifact", Value: "bbb"}},
				{Property: maven.Property{Name: "bbb.version", Value: "2.2.2"}},
				{Property: maven.Property{Name: "aaa.version", Value: "1.1.1"}},

				{Property: maven.Property{Name: "project.build.sourceEncoding", Value: "UTF-8"}},
				{Property: maven.Property{Name: "maven.compiler.source", Value: "1.7"}},
				{Property: maven.Property{Name: "maven.compiler.target", Value: "1.7"}},
				{Property: maven.Property{Name: "junit.version", Value: "4.12"}},
				{Property: maven.Property{Name: "def.version", Value: "2.3.4"}, Origin: "profile@profile-one"},
			},
			RequirementsWithProperties: []resolve.RequirementVersion{
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "junit:junit",
						},
						VersionType: resolve.Requirement,
						Version:     "${junit.version}",
					},
					// Type: dep.NewType(dep.Test), test scope is ignored to make resolution work.
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
							Name:   "org.example:aaa",
						},
						VersionType: resolve.Requirement,
						Version:     "${aaa.version}",
					},
					Type: depParentMgmt,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.example:${bbb.artifact}",
						},
						VersionType: resolve.Requirement,
						Version:     "${bbb.version}",
					},
					Type: depParentUpstreamMgmt,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.example:ccc",
						},
						VersionType: resolve.Requirement,
						Version:     "${ccc.version}",
					},
					Type: depImport,
				},
			},
			RequirementsFromOtherPOMs: []resolve.RequirementVersion{
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.example:aaa",
						},
						VersionType: resolve.Requirement,
						Version:     "1.1.1",
					},
					Type: depParentMgmt,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.example:bbb",
						},
						VersionType: resolve.Requirement,
						Version:     "2.2.2",
					},
					Type: depParentUpstreamMgmt,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.example:ccc",
						},
						VersionType: resolve.Requirement,
						Version:     "3.3.3",
					},
					Type: depImport,
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
	defer df.Close()

	depProfileTwoMgmt.AddAttr(dep.MavenArtifactType, "pom")
	depProfileTwoMgmt.AddAttr(dep.Scope, "import")

	changes := manifest.ManifestPatch{
		Deps: []manifest.DependencyPatch{
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
		EcosystemSpecific: manifest.MavenPropertyPatches{
			"": {
				"junit.version": "4.13.2",
			},
			"profile@profile-one": {
				"def.version": "2.3.5",
			},
		},
	}

	buf := new(bytes.Buffer)
	mavenIO := manifest.MavenManifestIO{}
	if err := mavenIO.Write(df, buf, changes); err != nil {
		t.Fatalf("unable to update Maven pom.xml: %v", err)
	}
	testutility.NewSnapshot().WithCRLFReplacement().MatchText(t, buf.String())
}
