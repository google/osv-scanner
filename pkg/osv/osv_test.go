// osv_test.go

package osv

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMakeRetryRequest(t *testing.T) {
	testCases := []struct {
		name             string
		statusCodes      []int
		expectedRespNil  bool
		expectedErr      bool
		expectedAttempts int
	}{
		{
			name:             "Success on first attempt (200)",
			statusCodes:      []int{200},
			expectedRespNil:  false,
			expectedErr:      false,
			expectedAttempts: 1,
		},
		{
			name:             "Client error (400), no retry",
			statusCodes:      []int{400},
			expectedRespNil:  false,
			expectedErr:      false,
			expectedAttempts: 1,
		},
		{
			name:             "Server error (500) x4, fail after retries",
			statusCodes:      []int{500, 500, 500, 500},
			expectedRespNil:  false, // resp is returned but contains server error
			expectedErr:      true,
			expectedAttempts: maxRetryAttempts,
		},
		{
			name:             "Server error (500) x2, then success (200)",
			statusCodes:      []int{500, 500, 200},
			expectedRespNil:  false,
			expectedErr:      false,
			expectedAttempts: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attempt := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if attempt < len(tc.statusCodes) {
					w.WriteHeader(tc.statusCodes[attempt])
				} else {
					// If more requests are made than status codes provided, repeat the last status code.
					w.WriteHeader(tc.statusCodes[len(tc.statusCodes)-1])
				}
				attempt++
			}))
			defer server.Close()

			// Override the QueryEndpoint for testing.
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

			// Assertions using standard library.
			if tc.expectedRespNil && resp != nil {
				t.Errorf("Expected response to be nil, but got: %v", resp)
			}
			if !tc.expectedRespNil && resp == nil {
				t.Errorf("Expected response to be non-nil, but got nil")
			}

			if tc.expectedErr && err == nil {
				t.Errorf("Expected an error, but got none")
			}
			if !tc.expectedErr && err != nil {
				t.Errorf("Did not expect an error, but got: %v", err)
			}

			if attempt != tc.expectedAttempts {
				t.Errorf("Expected %d attempts, but got: %d", tc.expectedAttempts, attempt)
			}
		})
	}
}
