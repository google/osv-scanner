// Package http provides HTTP utilities for OSV scanner.
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

// dryRunRoundTripper implements http.RoundTripper to intercept and print HTTP requests
// without actually sending them. This is used for the --dry-run flag to show users
// what data would be sent to OSV.dev without making actual network requests.
type dryRunRoundTripper struct {
	underlying http.RoundTripper
}

// NewDryRunRoundTripper creates a new dry-run round tripper that wraps an existing transport.
// If underlying is nil, http.DefaultTransport will be used.
func NewDryRunRoundTripper(underlying http.RoundTripper) http.RoundTripper {
	if underlying == nil {
		underlying = http.DefaultTransport
	}
	return &dryRunRoundTripper{
		underlying: underlying,
	}
}

// RoundTrip intercepts the HTTP request, prints its details, and returns a fake response.
func (rt *dryRunRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Print request details
	rt.printRequest(req)

	// Return a fake response to prevent the actual request from being made
	// This allows the scanner to continue its flow without network calls
	return rt.createFakeResponse(req), nil
}

// printRequest prints the HTTP request details in a human-readable format.
func (rt *dryRunRoundTripper) printRequest(req *http.Request) {
	cmdlogger.Infof("=== DRY RUN: HTTP Request Details ===")
	cmdlogger.Infof("Method: %s", req.Method)
	cmdlogger.Infof("URL: %s", req.URL.String())

	// Print headers (excluding sensitive ones)
	cmdlogger.Infof("Headers:")
	for key, values := range req.Header {
		// Skip authorization headers for security
		if strings.ToLower(key) == "authorization" ||
			strings.ToLower(key) == "cookie" {
			cmdlogger.Infof("  %s: [REDACTED]", key)
			continue
		}
		for _, value := range values {
			cmdlogger.Infof("  %s: %s", key, value)
		}
	}

	// Print body if present
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			cmdlogger.Infof("Body: [Error reading body: %v]", err)
		} else {
			// Restore the body for potential reuse
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// Try to format as JSON if possible
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, bodyBytes, "", "  "); err == nil {
				cmdlogger.Infof("Body (JSON):")
				for _, line := range strings.Split(prettyJSON.String(), "\n") {
					cmdlogger.Infof("  %s", line)
				}
			} else {
				// If not JSON, print as-is (truncated if too long)
				bodyStr := string(bodyBytes)
				if len(bodyStr) > 500 {
					bodyStr = bodyStr[:500] + "... [truncated]"
				}
				cmdlogger.Infof("Body: %s", bodyStr)
			}
		}
	}
	cmdlogger.Infof("=====================================")
}

// createFakeResponse creates a fake HTTP response to allow the scanner to continue
// without making actual network requests.
func (rt *dryRunRoundTripper) createFakeResponse(req *http.Request) *http.Response {
	// Create a fake response that indicates dry-run mode
	fakeBody := `{"dry_run": true, "message": "This is a dry-run response - no actual API call was made"}`

	return &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:    io.NopCloser(strings.NewReader(fakeBody)),
		Request: req,
	}
}

// DebugRoundTripper implements http.RoundTripper to print HTTP requests and responses
// for debugging purposes. Unlike dry-run, this actually sends the request.
type DebugRoundTripper struct {
	underlying http.RoundTripper
}

// NewDebugRoundTripper creates a new debug round tripper that wraps an existing transport.
func NewDebugRoundTripper(underlying http.RoundTripper) http.RoundTripper {
	if underlying == nil {
		underlying = http.DefaultTransport
	}
	return &DebugRoundTripper{
		underlying: underlying,
	}
}

// RoundTrip executes the HTTP request and prints both request and response details.
func (rt *DebugRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Print request details
	rt.printRequest(req)

	// Execute the actual request
	resp, err := rt.underlying.RoundTrip(req)
	if err != nil {
		cmdlogger.Infof("Request failed: %v", err)
		return resp, err
	}

	// Print response details
	rt.printResponse(resp)

	return resp, nil
}

// printRequest prints the HTTP request details for debugging.
func (rt *DebugRoundTripper) printRequest(req *http.Request) {
	cmdlogger.Infof("> %s %s", req.Method, req.URL.String())

	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, bodyBytes, "", "  "); err == nil {
				for _, line := range strings.Split(prettyJSON.String(), "\n") {
					cmdlogger.Infof("> %s", line)
				}
			}
		}
	}
}

// printResponse prints the HTTP response details for debugging.
func (rt *DebugRoundTripper) printResponse(resp *http.Response) {
	cmdlogger.Infof("< HTTP/%d.%d %d %s", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status)

	for key, values := range resp.Header {
		for _, value := range values {
			cmdlogger.Infof("< %s: %s", key, value)
		}
	}

	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, bodyBytes, "", "  "); err == nil {
				for _, line := range strings.Split(prettyJSON.String(), "\n") {
					cmdlogger.Infof("< %s", line)
				}
			}
		}
	}
}

// IsDryRunResponse checks if a response is a fake dry-run response.
func IsDryRunResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// Restore the body
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return false
	}

	dryRun, ok := result["dry_run"].(bool)
	return ok && dryRun
}

// DumpRequest creates a dump of the HTTP request for debugging purposes.
func DumpRequest(req *http.Request) (string, error) {
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return "", fmt.Errorf("failed to dump request: %w", err)
	}
	return string(dump), nil
}
