package sourceanalysis

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

// loggingProxy is a stand-in for a module proxy. It records every requested
// path and serves nothing, so a leak is observable without contacting a real
// proxy.
func loggingProxy(t *testing.T) (*httptest.Server, func() []string, func() int) {
	t.Helper()

	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))

	return srv,
		func() []string {
			mu.Lock()
			defer mu.Unlock()

			return append([]string(nil), paths...)
		},
		func() int {
			mu.Lock()
			defer mu.Unlock()

			return len(paths)
		}
}

// setTestProxy points the go command at the logging proxy and clears inherited
// settings that could bypass it or change module resolution behaviour.
func setTestProxy(t *testing.T, proxyURL string) {
	t.Helper()

	t.Setenv("GOPROXY", proxyURL)
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
}

func writeGoModule(t *testing.T, goMod, mainGo, goSum string) string {
	t.Helper()

	files := map[string]string{"go.mod": goMod, "main.go": mainGo}
	if goSum != "" {
		files["go.sum"] = goSum
	}

	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}

	return dir
}

func stdlibTestVuln(t *testing.T) *osvschema.Vulnerability {
	t.Helper()

	const fixture = `{
		"id": "GO-TEST-0001",
		"affected": [{
			"package": {"name": "stdlib", "ecosystem": "Go"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
			"ecosystem_specific": {"imports": [{"path": "net/http", "symbols": ["Get"]}]}
		}]
	}`

	vuln := &osvschema.Vulnerability{}
	if err := protojson.Unmarshal([]byte(fixture), vuln); err != nil {
		t.Fatalf("failed to build test vulnerability: %v", err)
	}

	return vuln
}

const (
	missingDepGoMod = `module example.com/offline-repro

go 1.21

require example.invalid/leakmod v1.2.3
`
	missingDepMain = `package main

import _ "example.invalid/leakmod"

func main() {}
`
	// A syntactically valid go.sum entry makes the go command attempt to
	// download the module from the configured proxy instead of failing early
	// with "missing go.sum entry".
	missingDepGoSum = `example.invalid/leakmod v1.2.3 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
example.invalid/leakmod v1.2.3/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`
)

//nolint:paralleltest // Uses t.Setenv to point the go command at the logging proxy.
func TestGoOfflineWithMissingModuleMakesNoProxyRequests(t *testing.T) {
	srv, recordedPaths, requestCount := loggingProxy(t)
	defer srv.Close()
	setTestProxy(t, srv.URL)

	modDir := writeGoModule(t, missingDepGoMod, missingDepMain, missingDepGoSum)
	_, err := runGovulncheck(modDir, []*osvschema.Vulnerability{stdlibTestVuln(t)}, "1.21", true)

	if err == nil {
		t.Fatal("expected offline analysis to stop cleanly when the dependency is missing")
	}
	if !errors.Is(err, errLocalDependencyUnavailable) {
		t.Fatalf("error = %v, want errLocalDependencyUnavailable", err)
	}
	if got := requestCount(); got != 0 {
		t.Fatalf("OFFLINE VIOLATION: module proxy received %d request(s): %v", got, recordedPaths())
	}

	t.Logf("offline analysis failed cleanly: %v", err)
	t.Logf("module proxy requests: %v", recordedPaths())
}

// TestOfflineRunDispatchMakesNoProxyRequests exercises the full dispatch path
// from Options.Offline down to the Go subprocess, not just runGovulncheck.
//
//nolint:paralleltest // Uses t.Setenv and temporarily replaces the global command logger.
func TestOfflineRunDispatchMakesNoProxyRequests(t *testing.T) {
	srv, recordedPaths, requestCount := loggingProxy(t)
	defer srv.Close()
	setTestProxy(t, srv.URL)

	// Not parallel: the command logger is global for the duration of this check.
	oldLogger := cmdlogger.GlobalLogger
	var logs bytes.Buffer
	cmdlogger.GlobalLogger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { cmdlogger.GlobalLogger = oldLogger })

	modDir := writeGoModule(t, missingDepGoMod, missingDepMain, missingDepGoSum)
	pkgs := []models.PackageVulns{
		{
			Package:         models.PackageInfo{Name: "stdlib", Version: "1.21"},
			Vulnerabilities: []*osvschema.Vulnerability{stdlibTestVuln(t)},
		},
	}
	source := models.SourceInfo{Path: filepath.Join(modDir, "go.mod"), Type: "lockfile"}

	run(source, pkgs, map[string]bool{"go": true}, Options{Offline: true}, exec.CommandContext)

	if got := requestCount(); got != 0 {
		t.Fatalf("OFFLINE VIOLATION: module proxy received %d request(s): %v", got, recordedPaths())
	}
	for _, pv := range pkgs {
		for _, group := range pv.Groups {
			if len(group.ExperimentalAnalysis) != 0 {
				t.Errorf("skipped analysis produced reachability data: %v", group.ExperimentalAnalysis)
			}
		}
	}

	output := logs.String()
	if !strings.Contains(output, "Skipping Go call analysis") {
		t.Errorf("missing skip diagnostic: %s", output)
	}
	if strings.Contains(output, "Failed to run code analysis") {
		t.Errorf("unavailable local dependency was reported as a scanner failure: %s", output)
	}

	t.Logf("module proxy requests: %v", recordedPaths())
}

//nolint:paralleltest // Uses t.Setenv to point the go command at the logging proxy.
func TestGoOnlineStillUsesModuleProxy(t *testing.T) {
	srv, recordedPaths, requestCount := loggingProxy(t)
	defer srv.Close()
	setTestProxy(t, srv.URL)

	modDir := writeGoModule(t, missingDepGoMod, missingDepMain, missingDepGoSum)
	_, err := runGovulncheck(modDir, []*osvschema.Vulnerability{stdlibTestVuln(t)}, "1.21", false)

	if got := requestCount(); got == 0 {
		t.Fatalf("online analysis no longer contacts the module proxy (err: %v)", err)
	}

	t.Logf("online analysis error (expected with a 404 proxy): %v", err)
	t.Logf("module proxy requests: %v", recordedPaths())
}

//nolint:paralleltest // Uses t.Setenv to point the go command at the logging proxy.
func TestGoOfflineWithHigherRequiredToolchainMakesNoDownload(t *testing.T) {
	srv, recordedPaths, requestCount := loggingProxy(t)
	defer srv.Close()
	setTestProxy(t, srv.URL)

	modDir := writeGoModule(t, "module example.com/higher-toolchain\n\ngo 1.999.0\n", "package main\n\nfunc main() {}\n", "")
	_, err := runGovulncheck(modDir, []*osvschema.Vulnerability{stdlibTestVuln(t)}, "1.21", true)

	if err == nil {
		t.Fatal("expected offline analysis to stop cleanly when the required toolchain is unavailable")
	}
	if !errors.Is(err, errLocalDependencyUnavailable) {
		t.Fatalf("error = %v, want errLocalDependencyUnavailable", err)
	}
	if got := requestCount(); got != 0 {
		t.Fatalf("OFFLINE VIOLATION: toolchain/proxy received %d request(s): %v", got, recordedPaths())
	}
	if !strings.Contains(strings.ToLower(err.Error()), "gotoolchain=local") {
		t.Errorf("error does not explain the local-toolchain restriction: %v", err)
	}

	t.Logf("offline analysis failed cleanly: %v", err)
	t.Logf("module proxy requests: %v", recordedPaths())
}

//nolint:paralleltest // Uses t.Setenv to point the go command at the logging proxy.
func TestGoOfflineWithLocallyAvailableCodeStillAnalyzes(t *testing.T) {
	srv, recordedPaths, requestCount := loggingProxy(t)
	defer srv.Close()
	setTestProxy(t, srv.URL)

	// Standard-library-only project: every dependency is already on disk.
	modDir := writeGoModule(t,
		"module example.com/local-only\n\ngo 1.21\n",
		`package main

import "net/http"

func main() { _, _ = http.Get("http://example.invalid") }
`,
		"",
	)

	findings, err := runGovulncheck(modDir, []*osvschema.Vulnerability{stdlibTestVuln(t)}, "1.21", true)
	if err != nil {
		t.Fatalf("offline analysis of a local-only module failed: %v", err)
	}
	if len(findings["GO-TEST-0001"]) == 0 {
		t.Fatalf("offline analysis produced no call findings: %v", findings)
	}
	if got := requestCount(); got != 0 {
		t.Fatalf("OFFLINE VIOLATION: module proxy received %d request(s): %v", got, recordedPaths())
	}

	t.Logf("offline findings: %d; module proxy requests: %v", len(findings["GO-TEST-0001"]), recordedPaths())
}
