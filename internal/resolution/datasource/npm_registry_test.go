package datasource_test

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/testutility"
)

type fakeNpmRegistry struct {
	mu         sync.Mutex
	repository map[string][]byte // path -> response
	expectAuth string
}

func (f *fakeNpmRegistry) setResponse(path string, response []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repository == nil {
		f.repository = make(map[string][]byte)
	}
	f.repository[path] = response
}

func (f *fakeNpmRegistry) setExpectAuth(auth string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expectAuth = auth
}

func (f *fakeNpmRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}
	f.mu.Lock()
	wantAuth := f.expectAuth
	resp, ok := f.repository[strings.TrimPrefix(path, "/")]
	f.mu.Unlock()

	if wantAuth != "" && r.Header.Get("Authorization") != wantAuth {
		w.WriteHeader(http.StatusUnauthorized)
		resp = []byte("unauthorized")
	} else if !ok {
		w.WriteHeader(http.StatusNotFound)
		resp = []byte("not found")
	}

	if _, err := w.Write(resp); err != nil {
		log.Fatalf("Write: %v", err)
	}
}

func TestNpmRegistryClient(t *testing.T) {
	t.Parallel()

	//nolint:gosec  // "Potential hardcoded credentials" :)
	const (
		auth      = "Y29vbDphdXRoCg=="
		authToken = "bmljZS10b2tlbgo="
	)

	reg1 := &fakeNpmRegistry{}
	reg1.setExpectAuth("Basic " + auth)

	b, err := os.ReadFile("./fixtures/npm_registry/fake-package.json")
	if err != nil {
		t.Fatalf("failed to read fake registry response file: %v", err)
	}
	reg1.setResponse("fake-package", b)

	b, err = os.ReadFile("./fixtures/npm_registry/fake-package-2.2.2.json")
	if err != nil {
		t.Fatalf("failed to read fake registry response file: %v", err)
	}
	reg1.setResponse("fake-package/2.2.2", b)

	reg2 := &fakeNpmRegistry{}
	reg2.setExpectAuth("Bearer " + authToken)

	b, err = os.ReadFile("./fixtures/npm_registry/@fake-registry-a.json")
	if err != nil {
		t.Fatalf("failed to read fake registry response file: %v", err)
	}
	reg2.setResponse("@fake-registry%2Fa", b)

	srv1 := httptest.NewServer(reg1)
	defer srv1.Close()
	srv2 := httptest.NewServer(reg2)
	defer srv2.Close()

	npmrcFiles := makeBlankNpmrcFiles(t)
	writeToNpmrc(t, npmrcFiles.project,
		"registry="+srv1.URL,
		"//"+strings.TrimPrefix(srv1.URL, "http://")+"/:_auth="+auth,
		"@fake-registry:registry="+srv2.URL,
		"//"+strings.TrimPrefix(srv2.URL, "http://")+"/:_authToken="+authToken,
	)

	cl, err := datasource.NewNpmRegistryAPIClient(filepath.Dir(npmrcFiles.project))
	if err != nil {
		t.Fatalf("failed creating npm api client: %v", err)
	}

	snap := testutility.NewSnapshot()
	vers, err := cl.Versions(context.Background(), "fake-package")
	if err != nil {
		t.Fatalf("failed getting versions: %v", err)
	}
	slices.Sort(vers.Versions)
	snap.MatchJSON(t, vers)

	vers2, err := cl.Versions(context.Background(), "@fake-registry/a")
	if err != nil {
		t.Fatalf("failed getting versions: %v", err)
	}
	slices.Sort(vers2.Versions)
	snap.MatchJSON(t, vers2)

	deps, err := cl.Dependencies(context.Background(), "fake-package", "2.2.2")
	if err != nil {
		t.Fatalf("failed getting dependencies: %v", err)
	}
	slices.Sort(deps.BundleDependencies)
	snap.MatchJSON(t, deps)

	json, err := cl.FullJSON(context.Background(), "fake-package", "2.2.2")
	if err != nil {
		t.Fatalf("failed getting full json: %v", err)
	}
	snap.WithCRLFReplacement().MatchText(t, json.String())
}
