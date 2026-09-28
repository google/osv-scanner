package http

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type rejectingTransport struct{}

func (rejectingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestWrapClientDoesNotSendOSVRequests(t *testing.T) {
	client := WrapClient(&http.Client{Transport: rejectingTransport{}})
	req, err := http.NewRequest(http.MethodPost, "https://api.osv.dev/v1/querybatch", strings.NewReader(`{"queries":[]}`))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("dry-run request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"results":[]}` {
		t.Fatalf("body = %q, want empty query results", body)
	}
}

func TestRedactHeader(t *testing.T) {
	for _, name := range []string{"Authorization", "Cookie", "X-API-Key", "X-Auth-Token", "X-Secret"} {
		if got := redactHeader(name, "sensitive"); got != "[REDACTED]" {
			t.Errorf("%s was not redacted: %q", name, got)
		}
	}
	if got := redactHeader("User-Agent", "osv-scanner"); got != "osv-scanner" {
		t.Errorf("non-sensitive header = %q", got)
	}
}
