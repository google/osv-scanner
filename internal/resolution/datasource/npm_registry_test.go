package datasource_test

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/testutility"
)

func TestNpmRegistryClient(t *testing.T) {
	t.Parallel()

	//nolint:gosec  // "Potential hardcoded credentials" :)
	const (
		auth      = "Y29vbDphdXRoCg=="
		authToken = "bmljZS10b2tlbgo="
	)

	srv1 := testutility.NewMockHTTPServer(t)
	srv1.SetAuthorization(t, "Basic "+auth)
	srv1.SetResponseFromFile(t, "/fake-package", "./fixtures/npm_registry/fake-package.json")
	srv1.SetResponseFromFile(t, "/fake-package/2.2.2", "./fixtures/npm_registry/fake-package-2.2.2.json")

	srv2 := testutility.NewMockHTTPServer(t)
	srv2.SetAuthorization(t, "Bearer "+authToken)
	srv2.SetResponseFromFile(t, "/@fake-registry%2fa", "./fixtures/npm_registry/@fake-registry-a.json")

	npmrcFile := createTempNpmrc(t, ".npmrc")
	writeToNpmrc(t, npmrcFile,
		"registry="+srv1.URL,
		"//"+strings.TrimPrefix(srv1.URL, "http://")+"/:_auth="+auth,
		"@fake-registry:registry="+srv2.URL,
		"//"+strings.TrimPrefix(srv2.URL, "http://")+"/:_authToken="+authToken,
	)

	cl, err := datasource.NewNpmRegistryAPIClient(filepath.Dir(npmrcFile))
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
