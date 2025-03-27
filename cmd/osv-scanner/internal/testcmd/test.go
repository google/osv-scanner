package testcmd

import (
	"testing"
)

// Test
// deprecated: use Run instead
func Test(t *testing.T, tc Case) {
	t.Helper()

	Run(t, tc)
}

// TestJSONWithCustomRules
// deprecated: use Run instead
func TestJSONWithCustomRules(t *testing.T, tc Case) {
	t.Helper()

	Run(t, tc)
}
