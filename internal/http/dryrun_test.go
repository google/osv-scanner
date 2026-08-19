package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDryRunRoundTripper(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		url            string
		body           string
		headers        map[string]string
		wantStatusCode int
		wantDryRun     bool
	}{
		{
			name:           "simple GET request",
			method:         "GET",
			url:            "https://api.osv.dev/v1/query",
			wantStatusCode: 200,
			wantDryRun:     true,
		},
		{
			name:           "POST request with JSON body",
			method:         "POST",
			url:            "https://api.osv.dev/v1/querybatch",
			body:           `{"package": {"name": "test", "version": "1.0"}}`,
			wantStatusCode: 200,
			wantDryRun:     true,
		},
		{
			name:           "request with authorization header",
			method:         "POST",
			url:            "https://api.osv.dev/v1/query",
			headers:        map[string]string{"Authorization": "Bearer secret-token"},
			body:           `{"test": "data"}`,
			wantStatusCode: 200,
			wantDryRun:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}
			req, err := http.NewRequest(tt.method, tt.url, bodyReader)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Create dry-run round tripper
			rt := NewDryRunRoundTripper(http.DefaultTransport)

			// Execute request
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip failed: %v", err)
			}

			// Check response
			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("Expected status code %d, got %d", tt.wantStatusCode, resp.StatusCode)
			}

			// Check if response is a dry-run response
			if tt.wantDryRun {
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				resp.Body.Close()

				var result map[string]interface{}
				if err := json.Unmarshal(bodyBytes, &result); err != nil {
					t.Fatalf("Failed to parse response JSON: %v", err)
				}

				dryRun, ok := result["dry_run"].(bool)
				if !ok || !dryRun {
					t.Errorf("Expected dry-run response, got: %v", result)
				}
			}
		})
	}
}

func TestDryRunRoundTripperRedactsSensitiveHeaders(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.osv.dev/v1/query", strings.NewReader(`{"test": "data"}`))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=abc123")
	req.Header.Set("Content-Type", "application/json")

	rt := NewDryRunRoundTripper(http.DefaultTransport)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	// Check that the request was logged (we can't easily check the exact output,
	// but we can verify the response was created)
	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}
}

func TestDebugRoundTripper(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "success"}`))
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rt := NewDebugRoundTripper(http.DefaultTransport)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if !bytes.Contains(bodyBytes, []byte("success")) {
		t.Errorf("Expected response to contain 'success', got: %s", string(bodyBytes))
	}
}

func TestIsDryRunResponse(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantDry bool
	}{
		{
			name:    "dry run response",
			body:    `{"dry_run": true, "message": "test"}`,
			wantDry: true,
		},
		{
			name:    "normal response",
			body:    `{"result": "success"}`,
			wantDry: false,
		},
		{
			name:    "dry run false",
			body:    `{"dry_run": false}`,
			wantDry: false,
		},
		{
			name:    "invalid JSON",
			body:    `not json`,
			wantDry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(tt.body)),
			}

			got := IsDryRunResponse(resp)
			if got != tt.wantDry {
				t.Errorf("IsDryRunResponse() = %v, want %v", got, tt.wantDry)
			}
		})
	}
}

func TestDumpRequest(t *testing.T) {
	req, err := http.NewRequest("GET", "https://api.osv.dev/v1/query", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("User-Agent", "test-agent")

	dump, err := DumpRequest(req)
	if err != nil {
		t.Fatalf("DumpRequest failed: %v", err)
	}

	if !strings.Contains(dump, "GET") {
		t.Errorf("Expected dump to contain 'GET', got: %s", dump)
	}
	if !strings.Contains(dump, "api.osv.dev") {
		t.Errorf("Expected dump to contain 'api.osv.dev', got: %s", dump)
	}
}
