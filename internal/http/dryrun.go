// Package http contains HTTP helpers used by osv-scanner.
package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

const osvAPIHost = "api.osv.dev"

type dryRunTransport struct {
	underlying http.RoundTripper
}

// WrapClient returns a copy of client which displays OSV.dev requests instead
// of sending them. Requests to other hosts retain their normal behavior.
func WrapClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	copy := *client
	copy.Transport = &dryRunTransport{underlying: transport}
	return &copy
}

func (t *dryRunTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || !strings.EqualFold(req.URL.Hostname(), osvAPIHost) {
		return t.underlying.RoundTrip(req)
	}

	printRequest(req)
	return dryRunResponse(req), nil
}

func printRequest(req *http.Request) {
	cmdlogger.Infof("Dry-run: would send %s %s to OSV.dev", req.Method, displayURL(req.URL))
	for name, values := range req.Header {
		for _, value := range values {
			cmdlogger.Infof("  %s: %s", name, redactHeader(name, value))
		}
	}

	if req.Body == nil {
		return
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		cmdlogger.Warnf("  request body unavailable: %v", err)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	var formatted bytes.Buffer
	if json.Indent(&formatted, body, "", "  ") == nil {
		for _, line := range strings.Split(formatted.String(), "\n") {
			cmdlogger.Infof("  %s", line)
		}
		return
	}
	cmdlogger.Infof("  %s", string(body))
}

func displayURL(raw *url.URL) string {
	copy := *raw
	query := copy.Query()
	for name := range query {
		lower := strings.ToLower(name)
		for _, sensitive := range []string{"token", "secret", "password", "key", "auth"} {
			if strings.Contains(lower, sensitive) {
				query.Set(name, "[REDACTED]")
				break
			}
		}
	}
	copy.RawQuery = query.Encode()
	return copy.String()
}

func redactHeader(name, value string) string {
	lower := strings.ToLower(name)
	for _, sensitive := range []string{"authorization", "cookie", "set-cookie", "proxy-authorization", "token", "secret", "password", "api-key", "apikey"} {
		if strings.Contains(lower, sensitive) {
			return "[REDACTED]"
		}
	}
	return value
}

func dryRunResponse(req *http.Request) *http.Response {
	body := `{}`
	if req.URL.Path == "/v1/querybatch" {
		body = `{"results":[]}`
	}
	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
