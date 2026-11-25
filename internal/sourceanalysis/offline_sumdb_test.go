package sourceanalysis

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	testDepModule    = "example.com/dep"
	testDepVersion   = "v1.0.0"
	sumdbVerifierKey = "sum.golang.org"
)

// endpointLogger records every request path received by a local stand-in server.
type endpointLogger struct {
	mu    sync.Mutex
	paths []string
	srv   *httptest.Server
}

func newEndpointLogger() *endpointLogger {
	l := &endpointLogger{}
	l.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.paths = append(l.paths, r.URL.Path)
		l.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))

	return l
}

func (l *endpointLogger) close() { l.srv.Close() }
func (l *endpointLogger) url() string {
	return l.srv.URL
}
func (l *endpointLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.paths...)
}
func (l *endpointLogger) count() int { return len(l.snapshot()) }

// cachedModuleFixture prepares a module cache holding example.com/dep v1.0.0
// together with a consumer module whose go.sum contains trusted checksums.
//
// Fixture population deliberately uses GOSUMDB=off and a loopback-only module
// proxy. This is test setup only; the production code path under test is never
// given those values.
type cachedModuleFixture struct {
	proxyDir     string
	cacheDir     string
	gopath       string
	consumerDir  string
	depGoMod     string
	depLib       string
	consumerGoMo string
	consumerMain string
	goSum        string
}

func prepareCachedModule(t *testing.T) *cachedModuleFixture {
	t.Helper()

	root := t.TempDir()

	depGoMod := "module " + testDepModule + "\n\ngo 1.21\n"
	depLib := "package dep\n\nfunc Hello() string { return \"hello\" }\n"
	depSrc := filepath.Join(root, "dep-src")
	if err := os.MkdirAll(depSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(depSrc, "go.mod"), []byte(depGoMod), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(depSrc, "lib.go"), []byte(depLib), 0o600); err != nil {
		t.Fatal(err)
	}

	proxyDir := filepath.Join(root, "proxy")
	if err := writeProxyTree(t, proxyDir, testDepModule, testDepVersion, depGoMod, depLib); err != nil {
		t.Fatalf("failed to build module proxy tree: %v", err)
	}
	proxySrv := httptest.NewServer(http.FileServer(http.Dir(proxyDir)))
	t.Cleanup(proxySrv.Close)

	cacheDir := filepath.Join(root, "gomodcache")
	gopath := filepath.Join(root, "gopath")

	consumerDir := filepath.Join(root, "consumer")
	if err := os.MkdirAll(consumerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	consumerGoMo := "module example.com/consumer\n\ngo 1.21\n\nrequire " + testDepModule + " " + testDepVersion + "\n"
	consumerMain := "package main\n\nimport (\n\t\"fmt\"\n\n\t\"" + testDepModule + "\"\n)\n\nfunc main() { fmt.Println(dep.Hello()) }\n"
	if err := os.WriteFile(filepath.Join(consumerDir, "go.mod"), []byte(consumerGoMo), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumerDir, "main.go"), []byte(consumerMain), 0o600); err != nil {
		t.Fatal(err)
	}

	env := append(cleanGoEnv(),
		"GOMODCACHE="+cacheDir,
		"GOPATH="+gopath,
		"GOPROXY="+proxySrv.URL,
		"GOSUMDB=off",
		"GOTOOLCHAIN=local",
		"GOTELEMETRY=off",
	)
	cmd := exec.CommandContext(context.Background(), "go", "mod", "download", testDepModule)
	cmd.Dir = consumerDir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture setup go mod download failed: %v\n%s", err, out)
	}

	goSum, err := os.ReadFile(filepath.Join(consumerDir, "go.sum"))
	if err != nil {
		t.Fatalf("fixture has no go.sum: %v", err)
	}
	if !strings.Contains(string(goSum), testDepModule+" "+testDepVersion) {
		t.Fatalf("fixture go.sum does not contain the trusted dependency checksum:\n%s", goSum)
	}

	return &cachedModuleFixture{
		proxyDir:     proxyDir,
		cacheDir:     cacheDir,
		gopath:       gopath,
		consumerDir:  consumerDir,
		depGoMod:     depGoMod,
		depLib:       depLib,
		consumerGoMo: consumerGoMo,
		consumerMain: consumerMain,
		goSum:        string(goSum),
	}
}

// cleanGoEnv removes settings that would otherwise leak between the host and
// the subprocess under test.
func cleanGoEnv() []string {
	drop := func(key string) bool {
		switch key {
		case "GOPROXY", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOFLAGS", "GOTOOLCHAIN", "GOTELEMETRY":
			return true
		}

		return false
	}

	var env []string
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && drop(key) {
			continue
		}
		env = append(env, kv)
	}

	return env
}

// writeProxyTree lays out a module proxy directory for one module version.
func writeProxyTree(t *testing.T, dir, modulePath, version, goMod, lib string) error {
	t.Helper()

	vdir := filepath.Join(dir, filepath.FromSlash(modulePath), "@v")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(vdir, "list"), []byte(version+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(vdir, version+".info"),
		[]byte(fmt.Sprintf(`{"Version":%q,"Time":"2024-01-01T00:00:00Z"}`, version)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(vdir, version+".mod"), []byte(goMod), 0o600); err != nil {
		return err
	}

	zipPath := filepath.Join(vdir, version+".zip")
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	prefix := modulePath + "@" + version + "/"
	for name, content := range map[string]string{"go.mod": goMod, "lib.go": lib} {
		w, err := zw.Create(prefix + name)
		if err != nil {
			f.Close()
			return err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			f.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	return nil
}

func depTestVuln(t *testing.T) *osvschema.Vulnerability {
	t.Helper()

	const fixture = `{
		"id": "GO-TEST-SUMDB-0001",
		"affected": [{
			"package": {"name": "` + testDepModule + `", "ecosystem": "Go"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
			"ecosystem_specific": {"imports": [{"path": "` + testDepModule + `", "symbols": ["Hello"]}]}
		}]
	}`

	vuln := &osvschema.Vulnerability{}
	if err := protojson.Unmarshal([]byte(fixture), vuln); err != nil {
		t.Fatalf("failed to build dependency vulnerability: %v", err)
	}

	return vuln
}

// copyConsumer creates an isolated copy of the prepared consumer module.
func (f *cachedModuleFixture) copyConsumer(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"go.mod":  f.consumerGoMo,
		"main.go": f.consumerMain,
		"go.sum":  f.goSum,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// projectFingerprint hashes every regular file below dir, including vendor/.
func projectFingerprint(t *testing.T, dir string) map[string]string {
	t.Helper()

	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec // test-only fixture tree
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = hashBytes(data)

		return nil
	})
	if err != nil {
		t.Fatalf("failed to fingerprint project dir: %v", err)
	}

	return out
}

func assertProjectUnchanged(t *testing.T, dir string, before map[string]string) {
	t.Helper()

	after := projectFingerprint(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("project files changed during analysis:\nbefore: %v\nafter:  %v", before, after)
	}
}

// offlineEndpoints installs logging proxy + checksum-database endpoints and
// points all relevant Go environment variables at them.
func offlineEndpoints(t *testing.T) (*endpointLogger, *endpointLogger) {
	t.Helper()

	proxy := newEndpointLogger()
	t.Cleanup(proxy.close)
	sumdb := newEndpointLogger()
	t.Cleanup(sumdb.close)

	t.Setenv("GOPROXY", proxy.url())
	t.Setenv("GOSUMDB", sumdbVerifierKey+" "+sumdb.url())
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOSUMDB", "")
	t.Setenv("GONOPROXY", "")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOTELEMETRY", "off")

	return proxy, sumdb
}

func assertNoNetwork(t *testing.T, proxy, sumdb *endpointLogger) {
	t.Helper()

	if got := proxy.count(); got != 0 {
		t.Fatalf("OFFLINE VIOLATION: module proxy received %d request(s): %v", got, proxy.snapshot())
	}
	if got := sumdb.count(); got != 0 {
		t.Fatalf("OFFLINE VIOLATION: checksum database received %d request(s): %v", got, sumdb.snapshot())
	}
	if paths := append(append([]string{}, proxy.snapshot()...), sumdb.snapshot()...); slicesContains(paths, "toolchain") {
		t.Fatalf("OFFLINE VIOLATION: toolchain download attempted: %v", paths)
	}
}

func slicesContains(values []string, substr string) bool {
	for _, v := range values {
		if strings.Contains(v, substr) {
			return true
		}
	}

	return false
}

// TestOfflineMissingModuleEmptyCache verifies that a dependency absent from
// the local cache is reported as unavailable without contacting any endpoint.
func TestOfflineMissingModuleEmptyCache(t *testing.T) {
	fixture := prepareCachedModule(t)
	project := fixture.copyConsumer(t)
	before := projectFingerprint(t, project)

	proxy, sumdb := offlineEndpoints(t)
	t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "empty-cache"))
	t.Setenv("GOPATH", fixture.gopath)

	findings, err := runGovulncheck(project, []*osvschema.Vulnerability{depTestVuln(t)}, "1.21", true)
	if err == nil || !errors.Is(err, errLocalDependencyUnavailable) {
		t.Fatalf("error = %v, want errLocalDependencyUnavailable", err)
	}
	if len(findings) != 0 {
		t.Errorf("unavailable analysis produced findings: %v", findings)
	}

	assertNoNetwork(t, proxy, sumdb)
	assertProjectUnchanged(t, project, before)
}

// TestOfflineTamperedModuleCacheFailsClosed verifies that cached contents that
// contradict a trusted go.sum record are rejected before any analysis.
func TestOfflineTamperedModuleCacheFailsClosed(t *testing.T) {
	fixture := prepareCachedModule(t)
	cache := filepath.Join(t.TempDir(), "cache")
	copyDir(t, fixture.cacheDir, cache)

	// Corrupt the cached zip and force Go to re-extract, so checksum
	// verification is actually performed rather than trusting the extracted
	// directory that was already on disk.
	zipPath := filepath.Join(cache, "cache", "download", testDepModule, "@v", testDepVersion+".zip")
	data, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("locate cached zip: %v", err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(zipPath, data, 0o600); err != nil { //nolint:gosec // generated test fixture path, not user input
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(cache, testDepModule+"@"+testDepVersion)); err != nil {
		t.Fatal(err)
	}

	project := fixture.copyConsumer(t)
	before := projectFingerprint(t, project)

	proxy, sumdb := offlineEndpoints(t)
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("GOPATH", fixture.gopath)

	findings, err := runGovulncheck(project, []*osvschema.Vulnerability{depTestVuln(t)}, "1.21", true)
	if err == nil || !errors.Is(err, errIntegrityVerificationFailed) {
		t.Fatalf("error = %v, want errIntegrityVerificationFailed", err)
	}
	if len(findings) != 0 {
		t.Errorf("integrity failure produced findings: %v", findings)
	}

	assertNoNetwork(t, proxy, sumdb)
	assertProjectUnchanged(t, project, before)
}

// TestOfflineHigherToolchainNoDownload verifies that a newer required Go
// toolchain is neither downloaded nor queried through the checksum database.
//
//nolint:paralleltest // offlineEndpoints uses t.Setenv to point Go at local logging endpoints.
func TestOfflineHigherToolchainNoDownload(t *testing.T) {
	project := writeGoModule(t,
		"module example.com/toolchain\n\ngo 1.999.0\n",
		"package main\n\nfunc main() {}\n",
		"",
	)
	before := projectFingerprint(t, project)

	proxy, sumdb := offlineEndpoints(t)

	_, err := runGovulncheck(project, []*osvschema.Vulnerability{depTestVuln(t)}, "1.21", true)
	if err == nil || !errors.Is(err, errLocalDependencyUnavailable) {
		t.Fatalf("error = %v, want errLocalDependencyUnavailable", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "gotoolchain=local") {
		t.Errorf("error does not explain the local-toolchain restriction: %v", err)
	}

	assertNoNetwork(t, proxy, sumdb)
	assertProjectUnchanged(t, project, before)
}

// TestOnlineControlStillContactsModuleProxy confirms that the online path is
// unchanged: with a cold cache the module proxy is still contacted.
func TestOnlineControlStillContactsModuleProxy(t *testing.T) {
	fixture := prepareCachedModule(t)
	project := fixture.copyConsumer(t)
	before := projectFingerprint(t, project)

	proxy := newEndpointLogger()
	defer proxy.close()
	sumdb := newEndpointLogger()
	defer sumdb.close()

	t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "empty-cache"))
	t.Setenv("GOPATH", fixture.gopath)
	t.Setenv("GOPROXY", proxy.url())
	t.Setenv("GOSUMDB", sumdbVerifierKey+" "+sumdb.url())
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOSUMDB", "")
	t.Setenv("GONOPROXY", "")
	t.Setenv("GOTOOLCHAIN", "auto")

	_, _ = runGovulncheck(project, []*osvschema.Vulnerability{depTestVuln(t)}, "1.21", false)

	if got := proxy.count(); got == 0 {
		t.Fatal("online analysis no longer contacts the module proxy")
	}
	t.Logf("online proxy requests: %v", proxy.snapshot())
	t.Logf("online checksum database requests: %v", sumdb.snapshot())
	assertProjectUnchanged(t, project, before)
}

// TestOfflineDispatchMissingChecksumKeepsVulnerabilities exercises the full
// source-analysis dispatch with a missing trusted checksum record: findings
// are preserved and no negative reachability result is produced.
func TestOfflineDispatchMissingChecksumKeepsVulnerabilities(t *testing.T) {
	fixture := prepareCachedModule(t)
	project := fixture.copyConsumer(t)
	if err := os.WriteFile(filepath.Join(project, "go.sum"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	proxy, sumdb := offlineEndpoints(t)
	t.Setenv("GOMODCACHE", fixture.cacheDir)
	t.Setenv("GOPATH", fixture.gopath)

	pkgs := []models.PackageVulns{
		{
			Package:         models.PackageInfo{Name: testDepModule, Version: testDepVersion, Ecosystem: "Go"},
			Vulnerabilities: []*osvschema.Vulnerability{depTestVuln(t)},
			Groups:          []models.GroupInfo{{IDs: []string{"GO-TEST-SUMDB-0001"}}},
		},
	}
	source := models.SourceInfo{Path: filepath.Join(project, "go.mod"), Type: "lockfile"}

	run(source, pkgs, map[string]bool{"go": true}, Options{Offline: true}, nil)

	assertNoNetwork(t, proxy, sumdb)
	for _, pv := range pkgs {
		for _, group := range pv.Groups {
			if len(group.ExperimentalAnalysis) != 0 {
				t.Errorf("skipped analysis produced reachability data: %v", group.ExperimentalAnalysis)
			}
			if !group.IsCalled() {
				t.Error("skipped analysis must not mark a vulnerability as unreachable")
			}
		}
	}
}

// TestRawGoModModeContactsChecksumDatabase documents the underlying Go
// behavior the offline policy defends against. It invokes `go list` directly
// (not through the scanner) with a module already in the cache but no trusted
// go.sum entry, while allowing Go to update module files (-mod=mod). The local
// checksum-database endpoint must receive a lookup: this is the leak that
// offline call analysis must never trigger.
func TestRawGoModModeContactsChecksumDatabase(t *testing.T) {
	t.Parallel()

	fixture := prepareCachedModule(t)
	project := fixture.copyConsumer(t)
	if err := os.WriteFile(filepath.Join(project, "go.sum"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	before := projectFingerprint(t, project)

	proxy := newEndpointLogger()
	defer proxy.close()
	sumdb := newEndpointLogger()
	defer sumdb.close()

	env := append(cleanGoEnv(),
		"GOMODCACHE="+fixture.cacheDir,
		"GOPATH="+fixture.gopath,
		"GOPROXY="+proxy.url(),
		"GOSUMDB="+sumdbVerifierKey+" "+sumdb.url(),
		"GOFLAGS=-mod=mod",
	)
	cmd := exec.CommandContext(context.Background(), "go", "list", "./...")
	cmd.Dir = project
	cmd.Env = env
	if err := cmd.Run(); err == nil {
		t.Fatal("expected the raw -mod=mod lookup against the logging endpoint to fail")
	}
	if got := sumdb.count(); got == 0 {
		t.Fatal("expected the raw -mod=mod path to contact the local checksum database")
	}
	if got := proxy.count(); got != 0 {
		t.Errorf("expected a cache hit, got proxy requests: %v", proxy.snapshot())
	}
	assertProjectUnchanged(t, project, before)

	t.Logf("checksum database requests: %v", sumdb.snapshot())
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path) //nolint:gosec // copies only a test-generated fixture tree
		if err != nil {
			return err
		}

		return os.WriteFile(target, data, info.Mode().Perm()) //nolint:gosec // copies only a test-generated fixture tree
	})
	if err != nil {
		t.Fatalf("copyDir failed: %v", err)
	}
}

// TestOfflineCachedModuleTrustedChecksum runs offline call analysis against a
// dependency that is present in the module cache with complete trusted go.sum
// records. Analysis must succeed and neither proxy nor checksum database may be
// contacted.
func TestOfflineCachedModuleTrustedChecksum(t *testing.T) {
	fixture := prepareCachedModule(t)
	project := fixture.copyConsumer(t)
	before := projectFingerprint(t, project)

	proxy, sumdb := offlineEndpoints(t)
	t.Setenv("GOMODCACHE", fixture.cacheDir)
	t.Setenv("GOPATH", fixture.gopath)

	findings, err := runGovulncheck(project, []*osvschema.Vulnerability{depTestVuln(t)}, "1.21", true)
	if err != nil {
		t.Fatalf("offline analysis of a fully cached module failed: %v", err)
	}
	if len(findings["GO-TEST-SUMDB-0001"]) == 0 {
		t.Fatalf("expected call findings for the cached dependency: %v", findings)
	}

	assertNoNetwork(t, proxy, sumdb)
	assertProjectUnchanged(t, project, before)
}

// TestOfflineCachedModuleMissingChecksum reproduces the risky configuration:
// the module is in the cache, its required go.sum entry is absent, and the
// ambient GOFLAGS asks Go to update modules (-mod=mod). No checksum database
// request may occur; the analysis must fail closed as locally unavailable and
// must not mutate the project.
func TestOfflineCachedModuleMissingChecksum(t *testing.T) {
	fixture := prepareCachedModule(t)
	project := fixture.copyConsumer(t)

	sumLine := testDepModule + " " + testDepVersion
	var filtered []string
	for line := range strings.SplitSeq(fixture.goSum, "\n") {
		if !strings.HasPrefix(line, sumLine) {
			filtered = append(filtered, line)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "go.sum"), []byte(strings.Join(filtered, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	// Fingerprint after the deliberate fixture mutation: the scan itself must
	// leave the project untouched.
	before := projectFingerprint(t, project)

	proxy, sumdb := offlineEndpoints(t)
	t.Setenv("GOMODCACHE", fixture.cacheDir)
	t.Setenv("GOPATH", fixture.gopath)
	// Simulate an inherited user setting that would otherwise allow go.sum edits.
	t.Setenv("GOFLAGS", "-mod=mod")

	_, err := runGovulncheck(project, []*osvschema.Vulnerability{depTestVuln(t)}, "1.21", true)
	if err == nil {
		t.Fatal("expected analysis to fail closed when a trusted checksum record is missing")
	}
	if !errors.Is(err, errLocalDependencyUnavailable) {
		t.Fatalf("error = %v, want errLocalDependencyUnavailable", err)
	}

	assertNoNetwork(t, proxy, sumdb)
	assertProjectUnchanged(t, project, before)
}
