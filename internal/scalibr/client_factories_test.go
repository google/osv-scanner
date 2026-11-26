package scalibr

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// defaultClientTransport follows a client returned by HTTPClient, for
// ClientFactories made without a base client, down to its transport.
func defaultClientTransport(t *testing.T, client *http.Client) *http.Transport {
	t.Helper()

	rt, ok := client.Transport.(*userAgentRoundTripper)
	if !ok {
		t.Fatalf("expected *userAgentRoundTripper, got %T", client.Transport)
	}
	transport, ok := rt.underlying.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", rt.underlying)
	}
	if transport == http.DefaultTransport {
		t.Fatal("expected the default client to use its own copy of http.DefaultTransport")
	}

	return transport
}

func TestClientFactories_HTTPClient_DefaultLimits(t *testing.T) {
	t.Parallel()

	cf := NewClientFactories(nil, "")
	t.Cleanup(func() {
		if err := cf.Close(); err != nil {
			t.Errorf("failed to close client factories: %v", err)
		}
	})
	client := cf.HTTPClient()
	transport := defaultClientTransport(t, client)

	// A literal rather than defaultResponseHeaderTimeout, so that this test also
	// builds, and fails, against code without the limit.
	if want := 75 * time.Second; transport.ResponseHeaderTimeout != want {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, want)
	}
	if transport.Proxy == nil {
		t.Error("expected the default transport to keep using the proxy settings from the environment")
	}
	// A limit on the whole request would also cut off long downloads, such as
	// the offline databases.
	if client.Timeout != 0 {
		t.Errorf("Timeout = %v, want no limit on the whole request", client.Timeout)
	}
}

// TestClientFactories_HTTPClient_ResponseHeaderTimeoutWiring checks that the
// response header limit of the default transport reaches requests sent through
// HTTPClient over HTTP/2, the protocol api.osv.dev uses. It lowers the limit to
// 1s itself, so it does not check the default value: DefaultLimits does.
func TestClientFactories_HTTPClient_ResponseHeaderTimeoutWiring(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/answered" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Read the request and never answer it.
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	cf := NewClientFactories(nil, "")
	t.Cleanup(func() {
		if err := cf.Close(); err != nil {
			t.Errorf("failed to close client factories: %v", err)
		}
	})
	client := cf.HTTPClient()
	transport := defaultClientTransport(t, client)
	transport.ResponseHeaderTimeout = time.Second
	transport.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	// A limit for the whole test, so that a regression fails instead of hanging.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	get := func(path string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		return client.Do(req)
	}

	// An answered request first, to check that the client speaks HTTP/2 to the server.
	resp, err := get("/answered")
	if err != nil {
		t.Fatalf("expected an answer, got %v", err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", resp.Proto)
	}

	resp, err = get("/never-answered")
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error for a request that is never answered")
	}
	// The test-wide limit is a timeout too, so check that it has not passed.
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() || ctx.Err() != nil {
		t.Errorf("expected the response header timeout, got %v", err)
	}
}
