package sourceanalysis

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func hashFileBytes(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	return hashBytes(data)
}

// TestExtractedDirTamperDetected isolates tampering of an already-extracted
// module directory while leaving the ZIP, .ziphash metadata, and project
// manifests untouched. Go's `go mod verify` hashes the extracted directory, so
// the scanner must classify this as an integrity failure and refuse analysis.
func TestExtractedDirTamperDetected(t *testing.T) {
	fixture := prepareCachedModule(t)
	cache := filepath.Join(t.TempDir(), "cache")
	copyDir(t, fixture.cacheDir, cache)

	zipPath := filepath.Join(cache, "cache", "download", testDepModule, "@v", testDepVersion+".zip")
	zipHashBefore := hashFileBytes(t, zipPath)
	metaPath := filepath.Join(cache, "cache", "download", testDepModule, "@v", testDepVersion+".ziphash")
	metaBefore := hashFileBytes(t, metaPath)

	extracted := filepath.Join(cache, testDepModule+"@"+testDepVersion, "lib.go")
	if err := os.Chmod(extracted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extracted, []byte("package dep\n\nfunc Hello() string { return \"tampered\" }\n"), 0o600); err != nil {
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
	if errors.Is(err, errLocalDependencyUnavailable) {
		t.Errorf("integrity failure was reported as a mere local unavailability: %v", err)
	}
	if !strings.Contains(err.Error(), "dir has been modified") {
		t.Errorf("error does not report extracted-directory modification: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("integrity failure produced call findings: %v", findings)
	}
	if got := hashFileBytes(t, zipPath); got != zipHashBefore {
		t.Error("cached ZIP was modified during the test")
	}
	if got := hashFileBytes(t, metaPath); got != metaBefore {
		t.Error(".ziphash metadata was modified during the test")
	}
	assertNoNetwork(t, proxy, sumdb)
	assertProjectUnchanged(t, project, before)
}

// TestGoSumRecordIndependence verifies the two go.sum record types separately.
func TestGoSumRecordIndependence(t *testing.T) {
	fixture := prepareCachedModule(t)
	var zipLine, modLine string
	for line := range strings.SplitSeq(fixture.goSum, "\n") {
		switch {
		case strings.HasPrefix(line, testDepModule+" "+testDepVersion+" h1:"):
			zipLine = line
		case strings.HasPrefix(line, testDepModule+" "+testDepVersion+"/go.mod h1:"):
			modLine = line
		}
	}
	if zipLine == "" || modLine == "" {
		t.Fatalf("fixture is missing records: zip=%q mod=%q", zipLine, modLine)
	}

	cases := []struct {
		name            string
		sums            string
		cold            bool
		wantSuccess     bool
		wantUnavailable bool
		wantIntegrity   bool
	}{
		{name: "both-records-present", sums: zipLine + "\n" + modLine + "\n", wantSuccess: true},
		{name: "zip-checksum-missing", sums: modLine + "\n", wantUnavailable: true},
		{name: "gomod-checksum-missing", sums: zipLine + "\n", wantUnavailable: true},
		{name: "both-checksums-missing", wantUnavailable: true},
		{
			name:          "invalid-zip-checksum",
			sums:          testDepModule + " " + testDepVersion + " h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" + modLine + "\n",
			wantIntegrity: true,
		},
		{name: "cold-module-cache", sums: zipLine + "\n" + modLine + "\n", cold: true, wantUnavailable: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := fixture.copyConsumer(t)
			if err := os.WriteFile(filepath.Join(project, "go.sum"), []byte(tc.sums), 0o600); err != nil {
				t.Fatal(err)
			}
			before := projectFingerprint(t, project)

			proxy, sumdb := offlineEndpoints(t)
			cache := fixture.cacheDir
			if tc.cold {
				cache = filepath.Join(t.TempDir(), "empty-cache")
			}
			t.Setenv("GOMODCACHE", cache)
			t.Setenv("GOPATH", fixture.gopath)

			findings, err := runGovulncheck(project, []*osvschema.Vulnerability{depTestVuln(t)}, "1.21", true)

			switch {
			case tc.wantSuccess:
				if err != nil {
					t.Fatalf("analysis failed: %v", err)
				}
				if len(findings["GO-TEST-SUMDB-0001"]) == 0 {
					t.Fatal("analysis produced no call findings")
				}
			case tc.wantUnavailable:
				if err == nil || !errors.Is(err, errLocalDependencyUnavailable) {
					t.Fatalf("error = %v, want errLocalDependencyUnavailable", err)
				}
				if len(findings) != 0 {
					t.Errorf("unavailable analysis produced findings: %v", findings)
				}
			case tc.wantIntegrity:
				if err == nil || !errors.Is(err, errIntegrityVerificationFailed) {
					t.Fatalf("error = %v, want errIntegrityVerificationFailed", err)
				}
				if len(findings) != 0 {
					t.Errorf("integrity failure produced findings: %v", findings)
				}
			}

			assertNoNetwork(t, proxy, sumdb)
			assertProjectUnchanged(t, project, before)
		})
	}
}

func writeVendorProject(t *testing.T, fixture *cachedModuleFixture, consistent bool) string {
	t.Helper()

	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  fixture.consumerGoMo,
		"main.go": fixture.consumerMain,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	vendorDep := filepath.Join(dir, "vendor", testDepModule)
	if err := os.MkdirAll(vendorDep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDep, "lib.go"), []byte(fixture.depLib), 0o600); err != nil {
		t.Fatal(err)
	}
	version := testDepVersion
	if !consistent {
		version = "v9.9.9"
	}
	modulesTxt := "# " + testDepModule + " " + version + "\n## explicit; go 1.21\n" + testDepModule + "\n"
	if err := os.WriteFile(filepath.Join(dir, "vendor", "modules.txt"), []byte(modulesTxt), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir
}

// TestVendorModeCompatibility verifies that vendor mode is preserved and that
// broken vendor configurations fail closed without network access.
func TestVendorModeCompatibility(t *testing.T) {
	fixture := prepareCachedModule(t)

	cases := []struct {
		name       string
		vendor     bool
		consistent bool
		goflags    string
		wantOK     bool
	}{
		{name: "no-vendor-cold-cache"},
		{name: "valid-vendor-auto", vendor: true, consistent: true, wantOK: true},
		{name: "valid-vendor-explicit", vendor: true, consistent: true, goflags: "-mod=vendor", wantOK: true},
		{name: "valid-vendor-explicit-with-other-flags", vendor: true, consistent: true, goflags: "-tags=x -mod=vendor", wantOK: true},
		{name: "inconsistent-vendor-metadata", vendor: true, goflags: "-mod=vendor"},
		{name: "vendor-mode-without-vendor-dir", goflags: "-mod=vendor"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := fixture.copyConsumer(t)
			if tc.vendor {
				project = writeVendorProject(t, fixture, tc.consistent)
			}
			before := projectFingerprint(t, project)

			proxy, sumdb := offlineEndpoints(t)
			t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "empty-cache"))
			t.Setenv("GOPATH", fixture.gopath)
			t.Setenv("GOFLAGS", tc.goflags)

			findings, err := runGovulncheck(project, []*osvschema.Vulnerability{depTestVuln(t)}, "1.21", true)

			if tc.wantOK {
				if err != nil {
					t.Fatalf("vendor analysis failed: %v", err)
				}
				if len(findings["GO-TEST-SUMDB-0001"]) == 0 {
					t.Fatal("vendor analysis produced no call findings")
				}
			} else {
				if err == nil || !errors.Is(err, errLocalDependencyUnavailable) {
					t.Fatalf("error = %v, want errLocalDependencyUnavailable", err)
				}
				if len(findings) != 0 {
					t.Errorf("skipped analysis produced findings: %v", findings)
				}
			}

			assertNoNetwork(t, proxy, sumdb)
			assertProjectUnchanged(t, project, before)
		})
	}
}
