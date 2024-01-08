package testutility

import (
	"os"
	"runtime"
	"testing"

	"github.com/google/osv-scanner/internal/testsnapshot"
)

// AcceptanceTests marks this test function as a extended that require additional dependencies
// automatically skipped unless running in a CI environment
func AcceptanceTests(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("TEST_ACCEPTANCE") != "true" {
		t.Skip("Skipping extended test: ", reason)
		testsnapshot.Skip(t, "Skipping extended test: ", reason)
	}
}

func ValueIfOnWindows(win, or string) string {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		return win
	}

	return or
}
