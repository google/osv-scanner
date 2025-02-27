package datasource_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/datasource"
	"github.com/google/osv-scanner/v2/internal/testutility"
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

func checkNpmRegistryRequest(t *testing.T, config datasource.NpmRegistryConfig, urlComponents []string, wantURL string, wantAuth string) {
	t.Helper()
	mt := &mockTransport{}
	httpClient := &http.Client{Transport: mt}
	resp, err := config.MakeRequest(context.Background(), httpClient, urlComponents...)
	if err != nil {
		t.Fatalf("error making request: %v", err)
	}
	defer resp.Body.Close()
	if len(mt.Requests) != 1 {
		t.Fatalf("unexpected number of requests made: %v", len(mt.Requests))
	}
	req := mt.Requests[0]
	gotURL := req.URL.String()
	if gotURL != wantURL {
		t.Errorf("MakeRequest() URL was %s, want %s", gotURL, wantURL)
	}
	gotAuth := req.Header.Get("Authorization")
	if gotAuth != wantAuth {
		t.Errorf("MakeRequest() Authorization was \"%s\", want \"%s\"", gotAuth, wantAuth)
	}
}

func TestLoadNpmRegistryConfig_WithNoRegistries(t *testing.T) {
	// t.Parallel()
	npmrcFiles := makeBlankNpmrcFiles(t)

	config, err := datasource.LoadNpmRegistryConfig(filepath.Dir(npmrcFiles.project))
	if err != nil {
		t.Fatalf("could not parse npmrc: %v", err)
	}

	if nRegs := len(config.ScopeURLs); nRegs != 1 {
		t.Errorf("expected 1 npm registry, got %v", nRegs)
	}

	checkNpmRegistryRequest(t, config, []string{"@test/package", "1.2.3"},
		"https://registry.npmjs.org/@test%2fpackage/1.2.3", "")
}

func TestLoadNpmRegistryConfig_WithAuth(t *testing.T) {
	// t.Parallel()
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

	checkNpmRegistryRequest(t, config, []string{"foo"}, "https://registry1.test.com/foo", "Basic bXVjaDphdXRoCg==")
	checkNpmRegistryRequest(t, config, []string{"@test0/bar"}, "https://registry1.test.com/@test0%2fbar", "Basic bXVjaDphdXRoCg==")
	checkNpmRegistryRequest(t, config, []string{"@test1/baz"}, "https://registry2.test.com/@test1%2fbaz", "Bearer c3VjaCB0b2tlbgo=")
	checkNpmRegistryRequest(t, config, []string{"@test2/test"}, "https://sub.registry2.test.com/@test2%2ftest", "Basic dXNlcjp3b3cK")
}

// Do not make this test parallel because it calls t.Setenv()
func TestLoadNpmRegistryConfig_WithOverrides(t *testing.T) {
	check := func(t *testing.T, npmrcFiles testNpmrcFiles, wantURLs [5]string) {
		t.Helper()
		config, err := datasource.LoadNpmRegistryConfig(filepath.Dir(npmrcFiles.project))
		if err != nil {
			t.Fatalf("could not parse npmrc: %v", err)
		}
		checkNpmRegistryRequest(t, config, []string{"pkg"}, wantURLs[0], "")
		checkNpmRegistryRequest(t, config, []string{"@general/pkg"}, wantURLs[1], "")
		checkNpmRegistryRequest(t, config, []string{"@global/pkg"}, wantURLs[2], "")
		checkNpmRegistryRequest(t, config, []string{"@user/pkg"}, wantURLs[3], "")
		checkNpmRegistryRequest(t, config, []string{"@project/pkg"}, wantURLs[4], "")
	}

	npmrcFiles := makeBlankNpmrcFiles(t)
	writeToNpmrc(t, npmrcFiles.project, "@project:registry=https://project.registry.com")
	writeToNpmrc(t, npmrcFiles.user, "@user:registry=https://user.registry.com")
	writeToNpmrc(t, npmrcFiles.global,
		"@global:registry=https://global.registry.com",
		"@general:registry=https://general.global.registry.com",
		"registry=https://global.registry.com",
	)
	wantURLs := [5]string{
		"https://global.registry.com/pkg",
		"https://general.global.registry.com/@general%2fpkg",
		"https://global.registry.com/@global%2fpkg",
		"https://user.registry.com/@user%2fpkg",
		"https://project.registry.com/@project%2fpkg",
	}
	check(t, npmrcFiles, wantURLs)

	// override global in user
	writeToNpmrc(t, npmrcFiles.user,
		"@general:registry=https://general.user.registry.com",
		"registry=https://user.registry.com",
	)
	wantURLs[0] = "https://user.registry.com/pkg"
	wantURLs[1] = "https://general.user.registry.com/@general%2fpkg"
	check(t, npmrcFiles, wantURLs)

	// override global/user in project
	writeToNpmrc(t, npmrcFiles.project,
		"@general:registry=https://general.project.registry.com",
		"registry=https://project.registry.com",
	)
	wantURLs[0] = "https://project.registry.com/pkg"
	wantURLs[1] = "https://general.project.registry.com/@general%2fpkg"
	check(t, npmrcFiles, wantURLs)

	// override global/user/project in environment variable
	t.Setenv("NPM_CONFIG_REGISTRY", "https://environ.registry.com")
	wantURLs[0] = "https://environ.registry.com/pkg"
	check(t, npmrcFiles, wantURLs)
}

func TestNpmRegistryAuths(t *testing.T) {
	// t.Parallel()
	b64enc := func(s string) string {
		t.Helper()
		return base64.StdEncoding.EncodeToString([]byte(s))
	}
	tests := []struct {
		name       string
		config     datasource.NpmrcConfig
		requestURL string
		wantAuth   string
	}{
		// Auth tests adapted from npm-registry-fetch
		// https://github.com/npm/npm-registry-fetch/blob/237d33b45396caa00add61e0549cf09fbf9deb4f/test/auth.js
		{
			name: "basic auth",
			config: datasource.NpmrcConfig{
				"//my.custom.registry/here/:username":  "user",
				"//my.custom.registry/here/:_password": b64enc("pass"),
			},
			requestURL: "https://my.custom.registry/here/",
			wantAuth:   "Basic " + b64enc("user:pass"),
		},
		{
			name: "token auth",
			config: datasource.NpmrcConfig{
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
			config: datasource.NpmrcConfig{
				"//my.custom.registry/:_auth":      "decafbad",
				"//my.custom.registry/here/:_auth": "c0ffee",
			},
			requestURL: "https://my.custom.registry/here//asdf/foo/bard/baz",
			wantAuth:   "Basic c0ffee",
		},
		{
			name: "_auth username:pass auth",
			config: datasource.NpmrcConfig{
				"//my.custom.registry/here/:_auth": b64enc("foo:bar"),
			},
			requestURL: "https://my.custom.registry/here/",
			wantAuth:   "Basic " + b64enc("foo:bar"),
		},
		{
			name: "ignore user/pass when _auth is set",
			config: datasource.NpmrcConfig{
				"//registry/:_auth":     b64enc("not:foobar"),
				"//registry/:username":  "foo",
				"//registry/:_password": b64enc("bar"),
			},
			requestURL: "http://registry/pkg/-/pkg-1.2.3.tgz",
			wantAuth:   "Basic " + b64enc("not:foobar"),
		},
		{
			name: "different hosts for uri vs registry",
			config: datasource.NpmrcConfig{
				"//my.custom.registry/here/:_authToken": "c0ffee",
				"//my.custom.registry/here/:token":      "nope",
			},
			requestURL: "https://some.other.host/",
			wantAuth:   "",
		},
		{
			name: "do not be thrown by other weird configs",
			config: datasource.NpmrcConfig{
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
			config: datasource.NpmrcConfig{
				"//custom.registry/:_authToken":         "less specific match",
				"//custom.registry/package:_authToken":  "exact match",
				"//custom.registry/package/:_authToken": "no match trailing slash",
			},
			requestURL: "http://custom.registry/package",
			wantAuth:   "Bearer exact match",
		},
		{
			name: "percent-encoding case-sensitivity",
			config: datasource.NpmrcConfig{
				"//custom.registry/:_authToken":                 "expected",
				"//custom.registry/@scope%2Fpackage:_authToken": "bad config",
			},
			requestURL: "http://custom.registry/@scope%2fpackage",
			wantAuth:   "Bearer expected",
		},
		{
			name: "require both user and pass",
			config: datasource.NpmrcConfig{
				"//custom.registry/:_authToken":  "fallback",
				"//custom.registry/foo:username": "user",
			},
			requestURL: "https://custom.registry/foo/bar",
			wantAuth:   "Bearer fallback",
		},
		{
			name: "don't inherit username",
			config: datasource.NpmrcConfig{
				"//custom.registry/:_authToken":       "fallback",
				"//custom.registry/foo:username":      "user",
				"//custom.registry/foo/bar:_password": b64enc("pass"),
			},
			requestURL: "https://custom.registry/foo/bar/baz",
			wantAuth:   "Bearer fallback",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()
			config := datasource.ParseNpmRegistryInfo(tt.config)
			// Send off requests to mockTransport to see the auth headers being added.
			mt := &mockTransport{}
			httpClient := &http.Client{Transport: mt}
			resp, err := config.Auths.GetAuth(tt.requestURL).Get(context.Background(), httpClient, tt.requestURL)
			if err != nil {
				t.Fatalf("error making request: %v", err)
			}
			defer resp.Body.Close()
			if len(mt.Requests) != 1 {
				t.Fatalf("unexpected number of requests made: %v", len(mt.Requests))
			}
			header := mt.Requests[0].Header
			if got := header.Get("Authorization"); got != tt.wantAuth {
				t.Errorf("authorization header got = \"%s\", want \"%s\"", got, tt.wantAuth)
			}
		})
	}
}
