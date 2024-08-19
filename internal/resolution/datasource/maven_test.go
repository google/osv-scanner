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
	client := &MavenRegistryAPIClient{
		registry: srv.URL,
	}
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

func TestGetMetadata(t *testing.T) {
	t.Parallel()

	srv := testutility.NewMockHTTPServer(t)
	client := &MavenRegistryAPIClient{
		registry: srv.URL,
	}
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
	    <snapshotVersions>
		  <snapshotVersion>
		    <extension>pom</extension>
		    <value>2.0.0-20240711.060746-8</value>
		    <updated>20240711060746</updated>
		  </snapshotVersion>
	    </snapshotVersions>
	  </versioning>
	</metadata>
	`))

	got, err := client.GetMetadata(context.Background(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "1.0.0", err)
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
			SnapshotVersions: []maven.SnapshotVersion{
				{
					Extension: "pom",
					Value:     "2.0.0-20240711.060746-8",
					Updated:   "20240711060746",
				},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetMetadata(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", got, want)
	}
}
