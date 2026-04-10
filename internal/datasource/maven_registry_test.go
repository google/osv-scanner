package datasource

import (
	"net/url"
	"reflect"
	"testing"

	"deps.dev/util/maven"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMavenRegistryAPIClient_GetProject(t *testing.T) {
	t.Parallel()

	srv := testutility.NewMockHTTPServer(t)
	client, _ := NewMavenRegistryAPIClient(MavenRegistry{URL: srv.URL, ReleasesEnabled: true})
	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))

	got, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
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
	client, _ := NewMavenRegistryAPIClient(MavenRegistry{URL: srv.URL, SnapshotsEnabled: true})
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

	got, err := client.GetProject(t.Context(), "org.example", "x.y.z", "3.3.1-SNAPSHOT")
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
	client, _ := NewMavenRegistryAPIClient(MavenRegistry{URL: srv.URL, ReleasesEnabled: true})
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

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to get parse URL %s: %v", srv.URL, err)
	}

	got, err := client.getArtifactMetadata(t.Context(), MavenRegistry{Parsed: u}, "org.example", "x.y.z")
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
	client, _ := NewMavenRegistryAPIClient(MavenRegistry{URL: srv.URL, SnapshotsEnabled: true})
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

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to get parse URL %s: %v", srv.URL, err)
	}

	got, err := client.getVersionMetadata(t.Context(), MavenRegistry{Parsed: u}, "org.example", "x.y.z", "3.3.1-SNAPSHOT")
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
	client, _ := NewMavenRegistryAPIClient(MavenRegistry{URL: dft.URL, ReleasesEnabled: true})
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
	// The untrusted-registry URL validator normally rejects loopback hosts,
	// so stub the resolver to pretend 127.0.0.1 is a public address for the
	// duration of this test.
	origLookup := lookupHost
	lookupHost = func(string) ([]string, error) { return []string{"203.0.113.1"}, nil }
	t.Cleanup(func() { lookupHost = origLookup })
	if err := client.AddRegistry(MavenRegistry{URL: srv.URL, ReleasesEnabled: true}); err != nil {
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

	gotProj, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
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

	gotVersions, err := client.GetVersions(t.Context(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions := []maven.String{"1.0.0", "2.0.0", "3.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}
}

func TestAddRegistry_RejectsUntrustedURL(t *testing.T) {
	t.Parallel()

	origLookup := lookupHost
	t.Cleanup(func() { lookupHost = origLookup })

	cases := []struct {
		name      string
		url       string
		resolveTo []string
	}{
		{name: "non-http scheme", url: "file:///etc/passwd", resolveTo: nil},
		{name: "ftp scheme", url: "ftp://example.com/repo", resolveTo: []string{"203.0.113.10"}},
		{name: "loopback literal", url: "http://127.0.0.1/repo", resolveTo: []string{"127.0.0.1"}},
		{name: "rfc1918 literal", url: "http://10.0.0.1/repo", resolveTo: []string{"10.0.0.1"}},
		{name: "link-local literal", url: "http://169.254.169.254/repo", resolveTo: []string{"169.254.169.254"}},
		{name: "dns-rebind to private", url: "http://evil.example.com/repo", resolveTo: []string{"192.168.1.1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookupHost = func(string) ([]string, error) { return tc.resolveTo, nil }
			client, err := NewMavenRegistryAPIClient(MavenRegistry{URL: "https://repo.maven.apache.org/maven2", ReleasesEnabled: true})
			if err != nil {
				t.Fatalf("NewMavenRegistryAPIClient: %v", err)
			}
			err = client.AddRegistry(MavenRegistry{URL: tc.url, ID: "hostile"})
			if err == nil {
				t.Fatalf("AddRegistry(%q) = nil, want error", tc.url)
			}
			if got := client.GetRegistries(); len(got) != 0 {
				t.Errorf("registry was added despite validation failure: %+v", got)
			}
		})
	}
}

func TestAddRegistry_ClearsTrustedForAuth(t *testing.T) {
	t.Parallel()

	origLookup := lookupHost
	lookupHost = func(string) ([]string, error) { return []string{"203.0.113.42"}, nil }
	t.Cleanup(func() { lookupHost = origLookup })

	client, err := NewMavenRegistryAPIClient(MavenRegistry{URL: "https://repo.maven.apache.org/maven2", ReleasesEnabled: true})
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient: %v", err)
	}

	// The caller tries to smuggle in TrustedForAuth=true; AddRegistry must drop it.
	if err := client.AddRegistry(MavenRegistry{URL: "https://attacker.example/repo", ID: "central", TrustedForAuth: true}); err != nil {
		t.Fatalf("AddRegistry: %v", err)
	}
	regs := client.GetRegistries()
	if len(regs) != 1 {
		t.Fatalf("expected 1 added registry, got %d", len(regs))
	}
	if regs[0].TrustedForAuth {
		t.Errorf("AddRegistry left TrustedForAuth=true for an untrusted registry")
	}
}

func TestAuthFor_OnlyTrustedRegistriesReceiveCredentials(t *testing.T) {
	t.Parallel()

	m := &MavenRegistryAPIClient{
		registryAuths: map[string]*HTTPAuthentication{
			"central": {Username: "u", Password: "p"},
		},
	}
	trusted := MavenRegistry{ID: "central", TrustedForAuth: true}
	if got := m.authFor(trusted); got == nil {
		t.Errorf("authFor(trusted) = nil, want credentials")
	}
	untrusted := MavenRegistry{ID: "central", TrustedForAuth: false}
	if got := m.authFor(untrusted); got != nil {
		t.Errorf("authFor(untrusted) returned credentials, leak")
	}
}
