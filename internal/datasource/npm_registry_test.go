package datasource_test

import (
	compare "cmp"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/v2/internal/datasource"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/tidwall/gjson"
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
	{
		const pkg = "fake-package"
		want := datasource.NpmRegistryVersions{
			Versions: []string{"1.0.0", "2.2.2"},
			Tags: map[string]string{
				"latest":   "1.0.0",
				"version1": "1.0.0",
				"version2": "2.2.2",
			},
		}
		got, err := cl.Versions(t.Context(), pkg)
		if err != nil {
			t.Fatalf("failed getting versions: %v", err)
		}
		if diff := cmp.Diff(want, got, cmpopts.SortSlices(compare.Less[string])); diff != "" {
			t.Errorf("Versions(\"%s\") (-want +got)\n%s", pkg, diff)
		}
	}
	{
		const pkg = "@fake-registry/a"
		want := datasource.NpmRegistryVersions{
			Versions: []string{"1.2.3", "2.3.4"},
			Tags:     map[string]string{"latest": "2.3.4"},
		}
		got, err := cl.Versions(t.Context(), pkg)
		if err != nil {
			t.Fatalf("failed getting versions: %v", err)
		}
		if diff := cmp.Diff(want, got, cmpopts.SortSlices(compare.Less[string])); diff != "" {
			t.Errorf("Versions(\"%s\") (-want +got)\n%s", pkg, diff)
		}
	}

	{
		const pkg = "fake-package"
		const ver = "2.2.2"
		want := datasource.NpmRegistryDependencies{
			Dependencies: map[string]string{
				"a": "^3.0.1",
				"b": "^2.0.1",
				"e": "^0.2.33",
				"f": "npm:g@^2.0.1",
			},
			DevDependencies: map[string]string{
				"c": "^1.1.1",
				"d": "^1.0.2",
			},
			PeerDependencies: map[string]string{
				"h": "^1.0.0",
			},
			OptionalDependencies: map[string]string{
				"e": "^0.2.33",
				"f": "npm:g@^2.0.1",
			},
			BundleDependencies: []string{
				"a",
			},
		}
		got, err := cl.Dependencies(t.Context(), pkg, ver)
		if err != nil {
			t.Fatalf("failed getting dependencies: %v", err)
		}
		if diff := cmp.Diff(want, got, cmpopts.SortSlices(compare.Less[string])); diff != "" {
			t.Errorf("Dependencies(\"%s\", \"%s\") (-want +got)\n%s", pkg, ver, diff)
		}
	}
	{
		const pkg = "fake-package"
		const ver = "2.2.2"
		want := gjson.Parse(`{
			"name": "fake-package",
			"version": "2.2.2",
			"main": "index.js",
			"scripts": {
				"test": "echo \"Error: no test specified\" && exit 1"
			},
			"author": "",
			"license": "ISC",
			"dependencies": {
				"a": "^3.0.1",
				"b": "^2.0.1",
				"e": "^0.2.33",
				"f": "npm:g@^2.0.1"
			},
			"devDependencies": {
				"c": "^1.1.1",
				"d": "^1.0.2"
			},
			"optionalDependencies": {
				"e": "^0.2.33",
				"f": "npm:g@^2.0.1"
			},
			"peerDependencies": {
				"h": "^1.0.0"
			},
			"bundleDependencies": [
				"a"
			],
			"_id": "fake-package@2.2.2",
			"_nodeVersion": "20.9.0",
			"_npmVersion": "10.1.0",
			"dist": {
				"integrity": "sha512-NWvNE9fxykrzSQVr1CSKchzkQr5qwplvgn3O/0JL46qM6BhoGlKRjLiaZYdo1byXJWLGthghOgGpUZiEL04HQQ==",
				"shasum": "8dc47515da4e67bb794a4c9c7f4750bb4d67c7fc",
				"tarball": "http://localhost:4873/fake-package/-/fake-package-2.2.2.tgz"
			},
			"contributors": []
		}`)
		got, err := cl.FullJSON(t.Context(), pkg, ver)
		if err != nil {
			t.Fatalf("failed getting full json: %v", err)
		}
		wantMap := want.Value().(map[string]any)
		gotMap := got.Value().(map[string]any)
		if diff := cmp.Diff(wantMap, gotMap, cmpopts.SortSlices(compare.Less[string])); diff != "" {
			t.Errorf("FullJSON(\"%s\", \"%s\") (-want +got)\n%s", pkg, ver, diff)
		}
	}
}
