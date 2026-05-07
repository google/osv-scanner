package pathfilter_test

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/utility/pathfilter"
)

func TestFilterPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "safe path",
			input:    "GHSA-1234",
			expected: "GHSA-1234",
		},
		{
			name:     "safe path with subdirs",
			input:    "npm/all.zip",
			expected: filepath.FromSlash("npm/all.zip"),
		},
		{
			name:     "path traversal attempt",
			input:    "../../GHSA-1234",
			expected: "GHSA-1234",
		},
		{
			name:     "nested path traversal attempt",
			input:    "npm/../../all.zip",
			expected: "all.zip",
		},
		{
			name:     "absolute path becomes relative",
			input:    "/etc/passwd",
			expected: filepath.FromSlash("etc/passwd"),
		},
		{
			name:     "absolute path with traversal",
			input:    "/tmp/../../etc/passwd",
			expected: filepath.FromSlash("etc/passwd"),
		},
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "only traversal",
			input:    "../../..",
			expected: ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pathfilter.FilterPath(tt.input)
			if got != tt.expected {
				t.Errorf("FilterPath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
