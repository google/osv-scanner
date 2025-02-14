package osvdev

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestOSVClient_makeRetryRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		statusCodes  []int
		wantErr      error
		wantAttempts int
	}{
		{
			name:         "success on first attempt",
			statusCodes:  []int{http.StatusOK},
			wantAttempts: 1,
		},
		{
			name:        "client error no retry",
			statusCodes: []int{http.StatusBadRequest},
			wantErr: extracttest.ContainsErrStr{
				Str: "client error: status=\"400 Bad Request\"",
			},
			wantAttempts: 1,
		},
		{
			name:         "server error then success",
			statusCodes:  []int{http.StatusInternalServerError, http.StatusOK},
			wantAttempts: 2,
		},
		{
			name:        "max retries on server error",
			statusCodes: []int{http.StatusInternalServerError, http.StatusInternalServerError, http.StatusInternalServerError, http.StatusInternalServerError},
			wantErr: extracttest.ContainsErrStr{
				Str: "max retries exceeded",
			},
			wantAttempts: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := DefaultClient()
			// Low multipliers to make the test run faster
			client.Config.JitterMultiplier = 0
			client.Config.BackoffDurationMultiplier = 0
			client.Config.MaxRetryAttempts = 4
			client.HTTPClient = &http.Client{Timeout: time.Second}

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

			resp, err := client.makeRetryRequest(func(hc *http.Client) (*http.Response, error) {
				//nolint:noctx // because this is test code
				return hc.Get(server.URL)
			})

			if attempts != tt.wantAttempts {
				t.Errorf("got %d attempts, want %d", attempts, tt.wantAttempts)
			}

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
				return
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
