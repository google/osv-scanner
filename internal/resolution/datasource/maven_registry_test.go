package datasource

import (
	"context"
	"reflect"
	"testing"

	"deps.dev/util/maven"
	"github.com/google/osv-scanner/internal/testutility"
)

func TestGetProject(t *testing.T) {
	t.Parallel()

	srv := testutility.NewMockHTTPServer(t)
	client, _ := NewMavenRegistryAPIClient(srv.URL)
	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))

	got, err := client.GetProject(context.Background(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "1.0.0", err)
	}
	want := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "1.0.0",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "1.0.0", got, want)
	}
}

func TestGetProjectSnapshot(t *testing.T) {
	t.Parallel()

	srv := testutility.NewMockHTTPServer(t)
	client, _ := NewMavenRegistryAPIClient(srv.URL)
	srv.SetResponse(t, "org/example/x.y.z/3.3.1-SNAPSHOT/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	  <snapshot>
	    <timestamp>20230302.052731</timestamp>
	    <buildNumber>9</buildNumber>
	  </snapshot>
	  <lastUpdated>20230302052731</lastUpdated>
	  <snapshotVersions>
	    <snapshotVersion>
	      <extension>jar</extension>
	      <value>3.3.1-20230302.052731-9</value>
	      <updated>20230302052731</updated>
	    </snapshotVersion>
	    <snapshotVersion>
	      <extension>pom</extension>
	      <value>3.3.1-20230302.052731-9</value>
	      <updated>20230302052731</updated>
	    </snapshotVersion>
	  </snapshotVersions>
	  </versioning>
	</metadata>
	`))
	srv.SetResponse(t, "org/example/x.y.z/3.3.1-SNAPSHOT/x.y.z-3.3.1-20230302.052731-9.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>3.3.1-SNAPSHOT</version>
	</project>
	`))

	got, err := client.GetProject(context.Background(), "org.example", "x.y.z", "3.3.1-SNAPSHOT")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "3.3.1-SNAPSHOT", err)
	}
	want := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "3.3.1-SNAPSHOT",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "3.3.1-SNAPSHOT", got, want)
	}
}

func TestGetArtifactMetadata(t *testing.T) {
	t.Parallel()

	srv := testutility.NewMockHTTPServer(t)
	client, _ := NewMavenRegistryAPIClient(srv.URL)
	srv.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>3.0</latest>
	    <release>3.0</release>
	    <versions>
	      <version>1.0</version>
	      <version>2.0</version>
		  <version>3.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))

	got, err := client.getArtifactMetadata(context.Background(), srv.URL, "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get artifact metadata for %s:%s: %v", "org.example", "x.y.z", err)
	}
	want := maven.Metadata{
		GroupID:    "org.example",
		ArtifactID: "x.y.z",
		Versioning: maven.Versioning{
			Latest:  "3.0",
			Release: "3.0",
			Versions: []maven.String{
				"1.0",
				"2.0",
				"3.0",
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetArtifactMetadata(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", got, want)
	}
}

func TestGetVersionMetadata(t *testing.T) {
	t.Parallel()

	srv := testutility.NewMockHTTPServer(t)
	client, _ := NewMavenRegistryAPIClient(srv.URL)
	srv.SetResponse(t, "org/example/x.y.z/3.3.1-SNAPSHOT/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	  <snapshot>
	    <timestamp>20230302.052731</timestamp>
	    <buildNumber>9</buildNumber>
	  </snapshot>
	  <lastUpdated>20230302052731</lastUpdated>
	  <snapshotVersions>
	    <snapshotVersion>
	      <extension>jar</extension>
	      <value>3.3.1-20230302.052731-9</value>
	      <updated>20230302052731</updated>
	    </snapshotVersion>
	    <snapshotVersion>
	      <extension>pom</extension>
	      <value>3.3.1-20230302.052731-9</value>
	      <updated>20230302052731</updated>
	    </snapshotVersion>
	  </snapshotVersions>
	  </versioning>
	</metadata>
	`))

	got, err := client.getVersionMetadata(context.Background(), srv.URL, "org.example", "x.y.z", "3.3.1-SNAPSHOT")
	if err != nil {
		t.Fatalf("failed to get metadata for %s:%s verion %s: %v", "org.example", "x.y.z", "3.3.1-SNAPSHOT", err)
	}
	want := maven.Metadata{
		GroupID:    "org.example",
		ArtifactID: "x.y.z",
		Versioning: maven.Versioning{
			Snapshot: maven.Snapshot{
				Timestamp:   "20230302.052731",
				BuildNumber: 9,
			},
			LastUpdated: "20230302052731",
			SnapshotVersions: []maven.SnapshotVersion{
				{
					Extension: "jar",
					Value:     "3.3.1-20230302.052731-9",
					Updated:   "20230302052731",
				},
				{
					Extension: "pom",
					Value:     "3.3.1-20230302.052731-9",
					Updated:   "20230302052731",
				},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("getVersionMetadata(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", got, want)
	}
}

func TestMultipleRegistry(t *testing.T) {
	t.Parallel()

	dft := testutility.NewMockHTTPServer(t)
	client, _ := NewMavenRegistryAPIClient(dft.URL)
	dft.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>3.0.0</latest>
	    <release>3.0.0</release>
	    <versions>
	      <version>2.0.0</version>
		  <version>3.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))
	dft.SetResponse(t, "org/example/x.y.z/2.0.0/x.y.z-2.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>2.0.0</version>
	</project>
	`))
	dft.SetResponse(t, "org/example/x.y.z/3.0.0/x.y.z-3.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>3.0.0</version>
	</project>
	`))

	srv := testutility.NewMockHTTPServer(t)
	if err := client.AddRegistry(srv.URL); err != nil {
		t.Fatalf("failed to add registry %s: %v", srv.URL, err)
	}
	srv.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>2.0.0</latest>
	    <release>2.0.0</release>
	    <versions>
	      <version>1.0.0</version>
		  <version>2.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))
	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))
	srv.SetResponse(t, "org/example/x.y.z/2.0.0/x.y.z-2.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>2.0.0</version>
	</project>
	`))

	gotProj, err := client.GetProject(context.Background(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "1.0.0", err)
	}
	wantProj := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "1.0.0",
		},
	}
	if !reflect.DeepEqual(gotProj, wantProj) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "1.0.0", gotProj, wantProj)
	}

	gotVersions, err := client.GetVersions(context.Background(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions := []maven.String{"1.0.0", "2.0.0", "3.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}
}
