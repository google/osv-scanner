package osvdev

import "github.com/google/osv-scanner/internal/version"

type ClientConfig struct {
	MaxConcurrentRequests      int
	MaxConcurrentBatchRequests int

	MaxRetryAttempts int
	JitterMultiplier float64
	UserAgent        string
}

// Default make a default client config
func Default() ClientConfig {
	return ClientConfig{
		MaxRetryAttempts:           4,
		JitterMultiplier:           2,
		UserAgent:                  "osv-scanner-v2-" + version.OSVVersion,
		MaxConcurrentRequests:      1000,
		MaxConcurrentBatchRequests: 10,
	}
}
