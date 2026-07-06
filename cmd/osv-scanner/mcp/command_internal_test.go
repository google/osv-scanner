package mcp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsLoopbackListenAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want bool
	}{
		{name: "localhost", addr: "localhost:8080", want: true},
		{name: "ipv4 loopback", addr: "127.0.0.1:8080", want: true},
		{name: "ipv6 loopback", addr: "[::1]:8080", want: true},
		{name: "all interfaces", addr: ":8080", want: false},
		{name: "ipv4 all interfaces", addr: "0.0.0.0:8080", want: false},
		{name: "public host", addr: "example.com:8080", want: false},
		{name: "missing port", addr: "localhost", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isLoopbackListenAddr(tt.addr); got != tt.want {
				t.Fatalf("isLoopbackListenAddr(%q) = %t, want %t", tt.addr, got, tt.want)
			}
		})
	}
}

func TestRequireBearerToken(t *testing.T) {
	t.Parallel()

	called := false
	handler := requireBearerToken(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), "secret")

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("missing token response code = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
	if called {
		t.Fatal("handler called without bearer token")
	}

	req = httptest.NewRequest(http.MethodGet, "/sse", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token response code = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
	if called {
		t.Fatal("handler called with wrong bearer token")
	}

	req = httptest.NewRequest(http.MethodGet, "/sse", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("valid token response code = %d, want %d", resp.Code, http.StatusNoContent)
	}
	if !called {
		t.Fatal("handler not called with valid bearer token")
	}
}

func TestValidateScanPathsRequiresWorkspaceDescendant(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	inside := filepath.Join(root, "project")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}

	roots, err := resolveWorkspaceRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	handler := scanHandler{workspaceRoots: roots}

	if _, err := handler.validateScanPaths([]string{inside}); err != nil {
		t.Fatalf("inside workspace path rejected: %v", err)
	}

	outside := t.TempDir()
	if _, err := handler.validateScanPaths([]string{outside}); err == nil {
		t.Fatal("outside workspace path accepted")
	}
}

func TestValidateScanPathsRejectsSymlinkEscape(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on some Windows builders")
	}

	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "outside-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	roots, err := resolveWorkspaceRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	handler := scanHandler{workspaceRoots: roots}

	if _, err := handler.validateScanPaths([]string{link}); err == nil {
		t.Fatal("symlink escape path accepted")
	}
}

func TestRedactWorkspaceRoots(t *testing.T) {
	t.Parallel()

	roots, err := resolveWorkspaceRoots([]string{t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	handler := scanHandler{workspaceRoots: roots}

	fullPath := filepath.Join(roots[0], "go.mod")
	got := handler.redactWorkspaceRoots("scanned " + fullPath)
	if strings.Contains(got, roots[0]) {
		t.Fatalf("redacted text still contains workspace root %q: %q", roots[0], got)
	}
	if !strings.Contains(got, "<workspace>") {
		t.Fatalf("redacted text = %q, want workspace marker", got)
	}
}
