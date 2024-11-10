package osv

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRetryOn5xx(t *testing.T) {
	attempt := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		w.WriteHeader(http.StatusInternalServerError) // 500
	}))
	defer server.Close()

	// Override the QueryEndpoint for testing
	originalQueryEndpoint := QueryEndpoint
	QueryEndpoint = server.URL
	defer func() { QueryEndpoint = originalQueryEndpoint }()

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	resp, err := makeRetryRequest(func() (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodPost, QueryEndpoint, nil)
		req.Header.Set("Content-Type", "application/json")
		return client.Do(req)
	})

	log.Printf("TestRetryOn5xx: resp = %v, err = %v", resp, err)

	// Assertion: resp should be nil
	if resp != nil {
		t.Errorf("Expected response to be nil after retries on 5xx errors, but got: %v", resp)
	}

	// Assertion: err should not be nil
	if err == nil {
		t.Errorf("Expected an error after retries on 5xx errors, but got none")
	}

	// Assertion: number of attempts should equal maxRetryAttempts
	if attempt != maxRetryAttempts {
		t.Errorf("Expected number of attempts to equal maxRetryAttempts (%d), but got: %d", maxRetryAttempts, attempt)
	}
}
