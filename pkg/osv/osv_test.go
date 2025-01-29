package osv

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMakeRetryRequest(t *testing.T) {
	t.Parallel()
	testutility.Skip(t, "This test takes a long time (14+ seconds)")

	tests := []struct {
		name          string
		statusCodes   []int
		expectedError string
		wantAttempts  int
	}{
		{
			name:         "success on first attempt",
			statusCodes:  []int{http.StatusOK},
			wantAttempts: 1,
		},
		{
			name:          "client error no retry",
			statusCodes:   []int{http.StatusBadRequest},
			expectedError: "client error: status=400",
			wantAttempts:  1,
		},
		{
			name:         "server error then success",
			statusCodes:  []int{http.StatusInternalServerError, http.StatusOK},
			wantAttempts: 2,
		},
		{
			name:          "max retries on server error",
			statusCodes:   []int{http.StatusInternalServerError, http.StatusInternalServerError, http.StatusInternalServerError, http.StatusInternalServerError},
			expectedError: "max retries exceeded",
			wantAttempts:  4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			attempts := 0
			idx := 0

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				attempts++
				status := tt.statusCodes[idx]
				if idx < len(tt.statusCodes)-1 {
					idx++
				}

				w.WriteHeader(status)
				message := fmt.Sprintf("response-%d", attempts)
				_, _ = w.Write([]byte(message))
			}))
			defer server.Close()

			client := &http.Client{Timeout: time.Second}

			resp, err := makeRetryRequest(func() (*http.Response, error) {
				//nolint:noctx
				return client.Get(server.URL)
			})

			if attempts != tt.wantAttempts {
				t.Errorf("got %d attempts, want %d", attempts, tt.wantAttempts)
			}

			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.expectedError)
				}
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %q", tt.expectedError, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp == nil {
				t.Fatal("expected non-nil response")
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			expectedBody := fmt.Sprintf("response-%d", attempts)
			if string(body) != expectedBody {
				t.Errorf("got body %q, want %q", string(body), expectedBody)
			}
		})
	}
}
