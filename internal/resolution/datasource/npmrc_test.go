package datasource_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/testutility"
)

// These tests rely on using 'globalconfig' and 'userconfig' in the package .npmrc to override their default locations.
// It's also possible for environment variables or the builtin npmrc to mess with these tests.
// TODO: Should test the default and other methods of setting the global/user config.

func createTempNpmrc(t *testing.T, filename string) string {
	t.Helper()
	dir := testutility.CreateTestDir(t)
	file := filepath.Join(dir, filename)
	f, err := os.Create(file)
	if err != nil {
		t.Fatalf("could not create test npmrc file: %v", err)
	}
	f.Close()

	return file
}

func writeToNpmrc(t *testing.T, file string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		t.Fatalf("could not write to test npmrc file: %v", err)
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			t.Fatalf("could not write to test npmrc file: %v", err)
		}
	}
}

type testNpmrcFiles struct {
	global  string
	user    string
	project string
}

func makeBlankNpmrcFiles(t *testing.T) testNpmrcFiles {
	t.Helper()
	var files testNpmrcFiles
	files.global = createTempNpmrc(t, "npmrc")
	files.user = createTempNpmrc(t, ".npmrc")
	files.project = createTempNpmrc(t, ".npmrc")
	writeToNpmrc(t, files.project, "globalconfig="+files.global, "userconfig="+files.user)

	return files
}

func checkNpmRegistryRequest(t *testing.T, config datasource.NpmRegistryConfig, urlComponents ...string) {
	t.Helper()
	req, err := config.BuildRequest(context.Background(), urlComponents...)
	if err != nil {
		t.Fatalf("error building request: %v", err)
	}

	snapshot := testutility.NewSnapshot()
	snapshot.MatchText(t, req.URL.String())
	snapshot.MatchJSON(t, req.Header["Authorization"])
}

func TestNpmrcNoRegistries(t *testing.T) {
	t.Parallel()
	npmrcFiles := makeBlankNpmrcFiles(t)

	config, err := datasource.LoadNpmRegistryConfig(filepath.Dir(npmrcFiles.project))
	if err != nil {
		t.Fatalf("could not parse npmrc: %v", err)
	}

	if nRegs := len(config.ScopeURLs); nRegs != 1 {
		t.Errorf("expected 1 npm registry, got %v", nRegs)
	}

	checkNpmRegistryRequest(t, config, "@test/package", "1.2.3")
}

func TestNpmrcRegistryAuth(t *testing.T) {
	t.Parallel()
	npmrcFiles := makeBlankNpmrcFiles(t)
	writeToNpmrc(t, npmrcFiles.project,
		"registry=https://registry1.test.com",
		"//registry1.test.com/:_auth=bXVjaDphdXRoCg==",
		"@test1:registry=https://registry2.test.com",
		"//registry2.test.com/:_authToken=c3VjaCB0b2tlbgo=",
		"@test2:registry=https://sub.registry2.test.com",
		"//sub.registry2.test.com:username=user",
		"//sub.registry2.test.com:_password=d293Cg==",
	)

	config, err := datasource.LoadNpmRegistryConfig(filepath.Dir(npmrcFiles.project))
	if err != nil {
		t.Fatalf("could not parse npmrc: %v", err)
	}

	checkNpmRegistryRequest(t, config, "foo")
	checkNpmRegistryRequest(t, config, "@test0/bar")
	checkNpmRegistryRequest(t, config, "@test1/baz")
	checkNpmRegistryRequest(t, config, "@test2/test")
}

// Do not make this test parallel because it calls t.Setenv()
func TestNpmrcRegistryOverriding(t *testing.T) {
	check := func(t *testing.T, npmrcFiles testNpmrcFiles) {
		t.Helper()
		config, err := datasource.LoadNpmRegistryConfig(filepath.Dir(npmrcFiles.project))
		if err != nil {
			t.Fatalf("could not parse npmrc: %v", err)
		}
		checkNpmRegistryRequest(t, config, "pkg")
		checkNpmRegistryRequest(t, config, "@general/pkg")
		checkNpmRegistryRequest(t, config, "@global/pkg")
		checkNpmRegistryRequest(t, config, "@user/pkg")
		checkNpmRegistryRequest(t, config, "@project/pkg")
	}

	npmrcFiles := makeBlankNpmrcFiles(t)
	writeToNpmrc(t, npmrcFiles.project, "@project:registry=https://project.registry.com")
	writeToNpmrc(t, npmrcFiles.user, "@user:registry=https://user.registry.com")
	writeToNpmrc(t, npmrcFiles.global,
		"@global:registry=https://global.registry.com",
		"@general:registry=https://general.global.registry.com",
		"registry=https://global.registry.com",
	)
	check(t, npmrcFiles)

	// override global in user
	writeToNpmrc(t, npmrcFiles.user,
		"@general:registry=https://general.user.registry.com",
		"registry=https://user.registry.com",
	)
	check(t, npmrcFiles)

	// override global/user in project
	writeToNpmrc(t, npmrcFiles.project,
		"@general:registry=https://general.project.registry.com",
		"registry=https://project.registry.com",
	)
	check(t, npmrcFiles)

	// override global/user/project in environment variable
	t.Setenv("NPM_CONFIG_REGISTRY", "https://environ.registry.com")
	check(t, npmrcFiles)
}

func TestNpmRegistryAuthOpts(t *testing.T) {
	t.Parallel()
	b64enc := func(s string) string {
		t.Helper()
		return base64.StdEncoding.EncodeToString([]byte(s))
	}
	tests := []struct {
		name       string
		opts       datasource.NpmRegistryAuthOpts
		requestURL string
		wantAuth   string
	}{
		// Auth tests adapted from npm-registry-fetch
		// https://github.com/npm/npm-registry-fetch/blob/237d33b45396caa00add61e0549cf09fbf9deb4f/test/auth.js
		{
			name: "basic auth",
			opts: datasource.NpmRegistryAuthOpts{
				"//my.custom.registry/here/:username":  "user",
				"//my.custom.registry/here/:_password": b64enc("pass"),
			},
			requestURL: "https://my.custom.registry/here/",
			wantAuth:   "Basic " + b64enc("user:pass"),
		},
		{
			name: "token auth",
			opts: datasource.NpmRegistryAuthOpts{
				"//my.custom.registry/here/:_authToken": "c0ffee",
				"//my.custom.registry/here/:token":      "nope",
				"//my.custom.registry/:_authToken":      "7ea",
				"//my.custom.registry/:token":           "nope",
			},
			requestURL: "https://my.custom.registry/here//foo/-/foo.tgz",
			wantAuth:   "Bearer c0ffee",
		},
		{
			name: "_auth auth",
			opts: datasource.NpmRegistryAuthOpts{
				"//my.custom.registry/:_auth":      "decafbad",
				"//my.custom.registry/here/:_auth": "c0ffee",
			},
			requestURL: "https://my.custom.registry/here//asdf/foo/bard/baz",
			wantAuth:   "Basic c0ffee",
		},
		{
			name: "_auth username:pass auth",
			opts: datasource.NpmRegistryAuthOpts{
				"//my.custom.registry/here/:_auth": b64enc("foo:bar"),
			},
			requestURL: "https://my.custom.registry/here/",
			wantAuth:   "Basic " + b64enc("foo:bar"),
		},
		{
			name: "ignore user/pass when _auth is set",
			opts: datasource.NpmRegistryAuthOpts{
				"//registry/:_auth":     b64enc("not:foobar"),
				"//registry/:username":  "foo",
				"//registry/:_password": b64enc("bar"),
			},
			requestURL: "http://registry/pkg/-/pkg-1.2.3.tgz",
			wantAuth:   "Basic " + b64enc("not:foobar"),
		},
		{
			name: "different hosts for uri vs registry",
			opts: datasource.NpmRegistryAuthOpts{
				"//my.custom.registry/here/:_authToken": "c0ffee",
				"//my.custom.registry/here/:token":      "nope",
			},
			requestURL: "https://some.other.host/",
			wantAuth:   "",
		},
		{
			name: "do not be thrown by other weird configs",
			opts: datasource.NpmRegistryAuthOpts{
				"@asdf:_authToken":                 "does this work?",
				"//registry.npmjs.org:_authToken":  "do not share this",
				"_authToken":                       "definitely do not share this, either",
				"//localhost:15443:_authToken":     "wrong",
				"//localhost:15443/foo:_authToken": "correct bearer token",
				"//localhost:_authToken":           "not this one",
				"//other-registry:_authToken":      "this should not be used",
				"@asdf:registry":                   "https://other-registry/",
			},
			requestURL: "http://localhost:15443/foo/@asdf/bar/-/bar-1.2.3.tgz",
			wantAuth:   "Bearer correct bearer token",
		},
		// Some extra tests, based on experimentation with npm config
		{
			name: "exact package path uri",
			opts: datasource.NpmRegistryAuthOpts{
				"//custom.registry/:_authToken":         "less specific match",
				"//custom.registry/package:_authToken":  "exact match",
				"//custom.registry/package/:_authToken": "no match trailing slash",
			},
			requestURL: "http://custom.registry/package",
			wantAuth:   "Bearer exact match",
		},
		{
			name: "percent-encoding case-sensitivity",
			opts: datasource.NpmRegistryAuthOpts{
				"//custom.registry/:_authToken":                 "expected",
				"//custom.registry/@scope%2Fpackage:_authToken": "bad config",
			},
			requestURL: "http://custom.registry/@scope%2fpackage",
			wantAuth:   "Bearer expected",
		},
		{
			name: "require both user and pass",
			opts: datasource.NpmRegistryAuthOpts{
				"//custom.registry/:_authToken":  "fallback",
				"//custom.registry/foo:username": "user",
			},
			requestURL: "https://custom.registry/foo/bar",
			wantAuth:   "Bearer fallback",
		},
		{
			name: "don't inherit username",
			opts: datasource.NpmRegistryAuthOpts{
				"//custom.registry/:_authToken":       "fallback",
				"//custom.registry/foo:username":      "user",
				"//custom.registry/foo/bar:_password": b64enc("pass"),
			},
			requestURL: "https://custom.registry/foo/bar/baz",
			wantAuth:   "Bearer fallback",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			header := make(http.Header)
			tt.opts.GetAuth(tt.requestURL).AddToHeader(header)
			if got := header.Get("Authorization"); got != tt.wantAuth {
				t.Errorf("authorization header got = \"%s\", want \"%s\"", got, tt.wantAuth)
			}
		})
	}
}
