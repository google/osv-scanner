package osvdev

import "github.com/google/osv-scanner/internal/version"

type ClientConfig struct {
	MaxConcurrentRequests      int
	MaxConcurrentBatchRequests int

	MaxRetryAttempts           int
	JitterMultiplier           float64
	BackoffDurationExponential float64
	BackoffDurationMultiplier  float64
	UserAgent                  string
}

// Default make a default client config
func DefaultConfig() ClientConfig {
	return ClientConfig{
		MaxRetryAttempts:           4,
		JitterMultiplier:           2,
		BackoffDurationExponential: 2,
		BackoffDurationMultiplier:  1,
		UserAgent:                  "osv-scanner-v2-" + version.OSVVersion,
		MaxConcurrentRequests:      1000,
		MaxConcurrentBatchRequests: 10,
	}
}
