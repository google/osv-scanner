package testutility

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

type MockHTTPServer struct {
	*httptest.Server
	mu            sync.Mutex
	response      map[string][]byte // path -> response
	authorization string            // expected Authorization header contents
}

// NewMockHTTPServer starts and returns a new simple HTTP Server for mocking basic requests.
// The Server will automatically be shut down with Close() in the test Cleanup function.
//
// Use the SetResponse / SetResponseFromFile to set the responses for specific URL paths.
func NewMockHTTPServer(t *testing.T) *MockHTTPServer {
	t.Helper()
	mock := &MockHTTPServer{response: make(map[string][]byte)}
	mock.Server = httptest.NewServer(mock)
	t.Cleanup(func() { mock.Server.Close() })

	return mock
}

// SetResponse sets the Server's response for the URL path to be response bytes.
func (m *MockHTTPServer) SetResponse(t *testing.T, path string, response []byte) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	path = strings.TrimPrefix(path, "/")
	m.response[path] = response
}

// SetResponseFromFile sets the Server's response for the URL path to be the contents of the file at filename.
func (m *MockHTTPServer) SetResponseFromFile(t *testing.T, path string, filename string) {
	t.Helper()
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read response file: %v", err)
	}
	m.SetResponse(t, path, b)
}

// SetAuthorization sets the contents of the 'Authorization' header the server expects for all endpoints.
//
// The incoming requests' headers must match the auth string exactly, otherwise the server will response with 401 Unauthorized.
// If authorization is unset or empty, the server will not require authorization.
func (m *MockHTTPServer) SetAuthorization(t *testing.T, auth string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authorization = auth
}

// ServeHTTP is the http.Handler for the underlying httptest.Server.
func (m *MockHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	wantAuth := m.authorization
	resp, ok := m.response[strings.TrimPrefix(r.URL.EscapedPath(), "/")]
	m.mu.Unlock()

	if wantAuth != "" && r.Header.Get("Authorization") != wantAuth {
		w.WriteHeader(http.StatusUnauthorized)
		resp = []byte("unauthorized")
	} else if !ok {
		w.WriteHeader(http.StatusNotFound)
		resp = []byte("not found")
	}

	if _, err := w.Write(resp); err != nil {
		log.Fatalf("Write: %v", err)
	}
}
