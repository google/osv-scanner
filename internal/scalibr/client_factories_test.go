package scalibr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientFactories_GRPCClientConn(t *testing.T) {
	t.Parallel()

	cf := NewClientFactories(nil, "test-agent/1.0")
	defer func() {
		if err := cf.Close(); err != nil {
			t.Errorf("failed to close client factories: %v", err)
		}
	}()

	conn, err := cf.GRPCClientConn("api.deps.dev:443")
	if err != nil {
		t.Fatalf("GRPCClientConn failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}

	// Calling again should return the cached connection.
	conn2, err := cf.GRPCClientConn("api.deps.dev:443")
	if err != nil {
		t.Fatalf("GRPCClientConn second call failed: %v", err)
	}
	if conn != conn2 {
		t.Errorf("expected cached connection to be returned")
	}
}

func TestClientFactories_HTTPClient_UserAgent(t *testing.T) {
	t.Parallel()

	var receivedUserAgent string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUserAgent = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cf := NewClientFactories(ts.Client(), "test-agent/1.0")
	client := cf.HTTPClient()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if receivedUserAgent != "test-agent/1.0" {
		t.Errorf("expected User-Agent %q, got %q", "test-agent/1.0", receivedUserAgent)
	}
}

func TestClientFactories_GoogleHTTPClient(t *testing.T) {
	t.Parallel()

	cf := NewClientFactories(nil, "")
	_, err := cf.GoogleHTTPClient(context.Background())
	if err == nil {
		t.Fatal("expected error from GoogleHTTPClient, got nil")
	}
}
