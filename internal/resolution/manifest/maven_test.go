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
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/resolution/datasource"
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

func mavenReqKey(t *testing.T, name, artifactType, classifier string) RequirementKey {
	t.Helper()
	var typ dep.Type
	if artifactType != "" {
		typ.AddAttr(dep.MavenArtifactType, artifactType)
	}
	if classifier != "" {
		typ.AddAttr(dep.MavenClassifier, classifier)
	}

	return MakeRequirementKey(resolve.RequirementVersion{
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

	mavenIO := MavenManifestIO{
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

	depType := depMgmt.Clone()
	depType.AddAttr(dep.MavenArtifactType, "pom")
	depType.AddAttr(dep.Scope, "import")

	depParent.AddAttr(dep.MavenArtifactType, "pom")

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
						Name:   "org.profile:abc",
					},
					VersionType: resolve.Requirement,
					Version:     "1.2.3",
				},
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
						Name:   "org.example:aaa",
					},
					VersionType: resolve.Requirement,
					Version:     "1.1.1",
				},
				Type: depMgmt,
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
				Type: depMgmt,
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
				Type: depMgmt,
			},
		},
		Groups: map[RequirementKey][]string{
			mavenReqKey(t, "junit:junit", "", ""):       {"test"},
			mavenReqKey(t, "org.import:xyz", "pom", ""): {"import"},
		},
		EcosystemSpecific: MavenManifestSpecific{
			Properties: []PropertyWithOrigin{
				{Property: maven.Property{Name: "project.build.sourceEncoding", Value: "UTF-8"}},
				{Property: maven.Property{Name: "maven.compiler.source", Value: "1.7"}},
				{Property: maven.Property{Name: "maven.compiler.target", Value: "1.7"}},
				{Property: maven.Property{Name: "junit.version", Value: "4.12"}},
				{Property: maven.Property{Name: "def.version", Value: "2.3.4"}, Origin: "profile@profile-one"},
			},
			OriginalRequirements: []DependencyWithOrigin{
				{
					Dependency: maven.Dependency{GroupID: "org.parent", ArtifactID: "parent-pom", Version: "1.1.1", Type: "pom"},
					Origin:     "parent",
				},
				{
					Dependency: maven.Dependency{GroupID: "junit", ArtifactID: "junit", Version: "${junit.version}", Scope: "test"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "abc", Version: "1.0.1"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "xyz", Version: "2.0.0"},
					Origin:     "management",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.import", ArtifactID: "import", Version: "1.0.0", Scope: "import", Type: "pom"},
					Origin:     "management",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.profile", ArtifactID: "abc", Version: "1.2.3"},
					Origin:     "profile@profile-one",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.profile", ArtifactID: "def", Version: "${def.version}"},
					Origin:     "profile@profile-one",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.import", ArtifactID: "xyz", Version: "6.6.6", Scope: "import", Type: "pom"},
					Origin:     "profile@profile-two@management",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.dep", ArtifactID: "plugin-dep", Version: "2.3.3"},
					Origin:     "plugin@org.plugin:plugin",
				},
			},
			RequirementsForUpdates: []resolve.RequirementVersion{
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
							Name:   "org.import:import",
						},
						VersionType: resolve.Requirement,
						Version:     "1.0.0",
					},
					Type: depType,
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
					Type: depType,
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
				},
			},
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("Maven manifest mismatch: %s", diff)
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

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(df); err != nil {
		t.Fatalf("failed to read from DepFile: %v", err)
	}

	depPatches := MavenDependencyPatches{
		"": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "abc",
					Type:       "jar",
				},
				NewRequire: "1.0.2",
			}: true,
		},
		"management": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "xyz",
					Type:       "jar",
				},
				NewRequire: "2.0.1",
			}: true,
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "extra-one",
					Type:       "jar",
				},
				NewRequire: "6.6.6",
			}: false,
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "extra-two",
					Type:       "jar",
				},
				NewRequire: "9.9.9",
			}: false,
		},
		"profile@profile-one": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.profile",
					ArtifactID: "abc",
					Type:       "jar",
				},
				NewRequire: "1.2.4",
			}: true,
		},
		"profile@profile-two@management": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.import",
					ArtifactID: "xyz",
					Type:       "pom",
				},
				NewRequire: "7.0.0",
			}: true,
		},
		"plugin@org.plugin:plugin": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.dep",
					ArtifactID: "plugin-dep",
					Type:       "jar",
				},
				NewRequire: "2.3.4",
			}: true,
		},
	}
	propertyPatches := MavenPropertyPatches{
		"": {
			"junit.version": "4.13.2",
		},
		"profile@profile-one": {
			"def.version": "2.3.5",
		},
	}

	out := new(bytes.Buffer)
	if err := write(buf, out, depPatches, propertyPatches); err != nil {
		t.Fatalf("unable to update Maven pom.xml: %v", err)
	}
	testutility.NewSnapshot().WithCRLFReplacement().MatchText(t, out.String())
}

func TestMavenWriteDM(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	df, err := lockfile.OpenLocalDepFile(filepath.Join(dir, "fixtures", "no-dependency-management.xml"))
	if err != nil {
		t.Fatalf("fail to open file: %v", err)
	}
	defer df.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(df); err != nil {
		t.Fatalf("failed to read from DepFile: %v", err)
	}

	depPatches := MavenDependencyPatches{
		"": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "junit",
					ArtifactID: "junit",
					Type:       "jar",
				},
				NewRequire: "4.13.2",
			}: true,
		},
		"parent": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.parent",
					ArtifactID: "parent-pom",
					Type:       "jar",
				},
				NewRequire: "1.2.0",
			}: true,
		},
		"management": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.management",
					ArtifactID: "abc",
					Type:       "jar",
				},
				NewRequire: "1.2.3",
			}: false,
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.management",
					ArtifactID: "xyz",
					Type:       "jar",
				},
				NewRequire: "2.3.4",
			}: false,
		},
	}

	out := new(bytes.Buffer)
	if err := write(buf, out, depPatches, MavenPropertyPatches{}); err != nil {
		t.Fatalf("unable to update Maven pom.xml: %v", err)
	}
	testutility.NewSnapshot().WithCRLFReplacement().MatchText(t, out.String())
}

func TestBuildPatches(t *testing.T) {
	t.Parallel()

	depProfileTwoMgmt.AddAttr(dep.MavenArtifactType, "pom")
	depProfileTwoMgmt.AddAttr(dep.Scope, "import")

	depParent.AddAttr(dep.MavenArtifactType, "pom")

	patches := []DependencyPatch{
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
				Name:   "org.example:property",
			},
			NewRequire: "1.0.1",
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
				Name:   "org.example:another-property",
			},
			NewRequire: "1.1.0",
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
		{
			Pkg: resolve.PackageKey{
				System: resolve.Maven,
				Name:   "org.parent:parent-pom",
			},
			Type:       depParent,
			NewRequire: "1.2.0",
		},
		{
			Pkg: resolve.PackageKey{
				System: resolve.Maven,
				Name:   "org.example:suggest",
			},
			Type:        depMgmt,
			OrigRequire: "1.0.0",
			NewRequire:  "2.0.0",
		},
		{
			Pkg: resolve.PackageKey{
				System: resolve.Maven,
				Name:   "org.example:override",
			},
			Type:       depMgmt,
			NewRequire: "2.0.0",
		},
	}
	specific := MavenManifestSpecific{
		Properties: []PropertyWithOrigin{
			{Property: maven.Property{Name: "property.version", Value: "1.0.0"}},
			{Property: maven.Property{Name: "no.update.minor", Value: "9"}},
			{Property: maven.Property{Name: "def.version", Value: "2.3.4"}, Origin: "profile@profile-one"},
		},
		OriginalRequirements: []DependencyWithOrigin{
			{
				Dependency: maven.Dependency{GroupID: "org.parent", ArtifactID: "parent-pom", Version: "1.2.0", Type: "pom"},
				Origin:     "parent",
			},
			{
				Dependency: maven.Dependency{GroupID: "junit", ArtifactID: "junit", Version: "${junit.version}", Scope: "test"},
			},
			{
				Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "abc", Version: "1.0.1"},
			},
			{
				Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "no-updates", Version: "9.9.9"},
			},
			{
				Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "property", Version: "${property.version}"},
			},
			{
				Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "property-no-update", Version: "1.${no.update.minor}"},
			},
			{
				Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "same-property", Version: "${property.version}"},
			},
			{
				Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "another-property", Version: "${property.version}"},
			},
			{
				Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "xyz", Version: "2.0.0"},
				Origin:     "management",
			},
			{
				Dependency: maven.Dependency{GroupID: "org.profile", ArtifactID: "abc", Version: "1.2.3"},
				Origin:     "profile@profile-one",
			},
			{
				Dependency: maven.Dependency{GroupID: "org.profile", ArtifactID: "def", Version: "${def.version}"},
				Origin:     "profile@profile-one",
			},
			{
				Dependency: maven.Dependency{GroupID: "org.import", ArtifactID: "xyz", Version: "6.6.6", Scope: "import", Type: "pom"},
				Origin:     "profile@profile-two@management",
			},
			{
				Dependency: maven.Dependency{GroupID: "org.dep", ArtifactID: "plugin-dep", Version: "2.3.3"},
				Origin:     "plugin@org.plugin:plugin",
			},
		},
	}
	wantDepPatches := MavenDependencyPatches{
		"": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "abc",
					Type:       "jar",
				},
				NewRequire: "1.0.2",
			}: true,
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "another-property",
					Type:       "jar",
				},
				NewRequire: "1.1.0",
			}: true,
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "property-no-update",
					Type:       "jar",
				},
				NewRequire: "2.0.0",
			}: true,
		},
		"management": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "xyz",
					Type:       "jar",
				},
				NewRequire: "2.0.1",
			}: true,
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.example",
					ArtifactID: "override",
					Type:       "jar",
				},
				NewRequire: "2.0.0",
			}: false,
		},
		"profile@profile-one": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.profile",
					ArtifactID: "abc",
					Type:       "jar",
				},
				NewRequire: "1.2.4",
			}: true,
		},
		"profile@profile-two@management": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.import",
					ArtifactID: "xyz",
					Type:       "pom",
				},
				NewRequire: "6.7.0",
			}: true,
		},
		"plugin@org.plugin:plugin": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.dep",
					ArtifactID: "plugin-dep",
					Type:       "jar",
				},
				NewRequire: "2.3.4",
			}: true,
		},
		"parent": map[MavenPatch]bool{
			{
				DependencyKey: maven.DependencyKey{
					GroupID:    "org.parent",
					ArtifactID: "parent-pom",
					Type:       "pom",
				},
				NewRequire: "1.2.0",
			}: true,
		},
	}
	wantPropertyPatches := MavenPropertyPatches{
		"": {
			"property.version": "1.0.1",
		},
		"profile@profile-one": {
			"def.version": "2.3.5",
		},
	}

	depPatches, propertyPatches, err := buildPatches(patches, specific)
	if err != nil {
		t.Fatalf("failed to build patches: %v", err)
	}
	if diff := cmp.Diff(depPatches, wantDepPatches); diff != "" {
		t.Errorf("depednecy patches mismatch: %s", diff)
	}
	if diff := cmp.Diff(propertyPatches, wantPropertyPatches); diff != "" {
		t.Errorf("property patches mismatch: %s", diff)
	}
}

func TestGeneratePropertyPatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s1       string
		s2       string
		possible bool
		patches  map[string]string
	}{
		{"${version}", "1.2.3", true, map[string]string{"version": "1.2.3"}},
		{"${major}.2.3", "1.2.3", true, map[string]string{"major": "1"}},
		{"1.${minor}.3", "1.2.3", true, map[string]string{"minor": "2"}},
		{"1.2.${patch}", "1.2.3", true, map[string]string{"patch": "3"}},
		{"${major}.${minor}.${patch}", "1.2.3", true, map[string]string{"major": "1", "minor": "2", "patch": "3"}},
		{"${major}.2.3", "2.0.0", false, map[string]string{}},
		{"1.${minor}.3", "2.0.0", false, map[string]string{}},
	}
	for _, test := range tests {
		patches, ok := generatePropertyPatches(test.s1, test.s2)
		if ok != test.possible || !reflect.DeepEqual(patches, test.patches) {
			t.Errorf("generatePropertyPatches(%s, %s): got %v %v, want %v %v", test.s1, test.s2, patches, ok, test.patches, test.possible)
		}
	}
}
