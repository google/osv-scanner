package datasource_test

import (
	"context"
	"fmt"
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

	if nRegs := len(config); nRegs != 1 {
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
