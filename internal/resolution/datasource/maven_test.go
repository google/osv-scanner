package datasource

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"deps.dev/util/maven"
)

type fakeMavenRegistry struct {
	mu         sync.Mutex
	repository map[string]string // path -> response
}

func (f *fakeMavenRegistry) setResponse(path, response string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repository == nil {
		f.repository = make(map[string]string)
	}
	f.repository[path] = response
}

func (f *fakeMavenRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	resp, ok := f.repository[strings.TrimPrefix(r.URL.Path, "/")]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		resp = "not found"
	}
	if _, err := io.WriteString(w, resp); err != nil {
		log.Fatalf("WriteString: %v", err)
	}
}

func TestGetProject(t *testing.T) {
	t.Parallel()

	fakeMaven := &fakeMavenRegistry{}
	srv := httptest.NewServer(fakeMaven)
	defer srv.Close()
	client := &MavenRegistryAPIClient{
		Registry: srv.URL,
	}

	fakeMaven.setResponse("org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", `
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`)
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
