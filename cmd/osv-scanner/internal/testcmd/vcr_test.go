package testcmd

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

func TestToComparableRequest(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://api.osv.dev/v1/querybatch", bytes.NewReader([]byte(`{"queries":[{"version":"1.0.2","package":{"name":"balanced-match","ecosystem":"npm"}}]} `)))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Length", "90")

	gotReq, err := toComparableRequest(req)
	if err != nil {
		t.Fatalf("toComparableRequest failed: %v", err)
	}

	if gotReq.Method != http.MethodPost {
		t.Errorf("expected Method to be %q, got %q", http.MethodPost, gotReq.Method)
	}
	if gotReq.URL != "https://api.osv.dev/v1/querybatch" {
		t.Errorf("expected URL to be %q, got %q", "https://api.osv.dev/v1/querybatch", gotReq.URL)
	}

	// User-Agent and Content-Length should be deleted
	if gotReq.Headers.Get("User-Agent") != "" {
		t.Errorf("expected User-Agent to be removed")
	}
	if gotReq.Headers.Get("Content-Length") != "" {
		t.Errorf("expected Content-Length to be removed")
	}
	if gotReq.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type to be %q, got %q", "application/json", gotReq.Headers.Get("Content-Type"))
	}

	expectedBody := `{
  "queries": [
    {
      "package": {
        "ecosystem": "npm",
        "name": "balanced-match"
      },
      "version": "1.0.2"
    }
  ]
}
`
	if gotReq.Body != expectedBody {
		t.Errorf("expected body:\n%s\ngot:\n%s", expectedBody, gotReq.Body)
	}

	// Request Body must be readable again
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read request body after conversion: %v", err)
	}
	if string(bodyBytes) != `{"queries":[{"version":"1.0.2","package":{"name":"balanced-match","ecosystem":"npm"}}]} ` {
		t.Errorf("request body was not preserved: %s", string(bodyBytes))
	}
}

func TestCassetteToComparableRequest(t *testing.T) {
	t.Parallel()

	cassReq := cassette.Request{
		Method: http.MethodPost,
		URL:    "https://api.osv.dev/v1/querybatch",
		Headers: http.Header{
			"Content-Type":   []string{"application/json"},
			"User-Agent":     []string{"Mozilla/5.0"},
			"Content-Length": []string{"90"},
		},
		Body: `{"queries":[{"version":"1.0.2","package":{"name":"balanced-match","ecosystem":"npm"}}]} `,
	}

	gotReq := cassetteToComparableRequest(cassReq)

	if gotReq.Method != http.MethodPost {
		t.Errorf("expected Method to be %q, got %q", http.MethodPost, gotReq.Method)
	}
	if gotReq.URL != "https://api.osv.dev/v1/querybatch" {
		t.Errorf("expected URL to be %q, got %q", "https://api.osv.dev/v1/querybatch", gotReq.URL)
	}

	// User-Agent and Content-Length should be deleted
	if gotReq.Headers.Get("User-Agent") != "" {
		t.Errorf("expected User-Agent to be removed")
	}
	if gotReq.Headers.Get("Content-Length") != "" {
		t.Errorf("expected Content-Length to be removed")
	}
	if gotReq.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type to be %q, got %q", "application/json", gotReq.Headers.Get("Content-Type"))
	}

	expectedBody := `{
  "queries": [
    {
      "package": {
        "ecosystem": "npm",
        "name": "balanced-match"
      },
      "version": "1.0.2"
    }
  ]
}
`
	if gotReq.Body != expectedBody {
		t.Errorf("expected body:\n%s\ngot:\n%s", expectedBody, gotReq.Body)
	}
}
