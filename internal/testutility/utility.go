package testutility

import (
	"flag"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

// applyWindowsReplacements will replace any matching strings if on Windows
func applyWindowsReplacements(content string, replacements map[string]string) string {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		for match, replacement := range replacements {
			content = strings.ReplaceAll(content, match, replacement)
		}
	}

	return content
}

// CleanSnapshots ensures that snapshots are relevant and sorted for consistency
func CleanSnapshots(m *testing.M) {
	snaps.Clean(m, snaps.CleanOpts{Sort: true})
}

// Skip is equivalent to t.Log followed by t.SkipNow, but allows tracking of
// what snapshots are skipped so that they're not marked as obsolete
func Skip(t *testing.T, args ...any) {
	t.Helper()

	snaps.Skip(t, args...)
}

// isThisTestRunTarget tries to determine if the currently running test has been
// targeted with the -run flag, by comparing the flags value to [testing.T.Name]
//
// Since this just does a direct comparison, it will not match for regex patterns
func isThisTestRunTarget(t *testing.T) bool {
	t.Helper()

	runOnly := flag.Lookup("test.run").Value.String()

	return runOnly == t.Name()
}

// IsAcceptanceTesting returns true if the test suite is being run with acceptance tests enabled
func IsAcceptanceTesting() bool {
	return os.Getenv("TEST_ACCEPTANCE") == "true"
}

// SkipIfNotAcceptanceTesting marks the test as skipped unless the test suite is
// being run with acceptance tests enabled, as indicated by IsAcceptanceTesting,
// or the test is being run specifically with the -run flag
func SkipIfNotAcceptanceTesting(t *testing.T, reason string) {
	t.Helper()

	if !IsAcceptanceTesting() && !isThisTestRunTarget(t) {
		Skip(t, "Skipping extended test: ", reason)
	}
}

func ValueIfOnWindows(win, or string) string {
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		return win
	}

	return or
}

// CreateTestDir makes a temporary directory for use in testing that involves
// writing and reading files from disk, which is automatically cleaned up
// when testing finishes
func CreateTestDir(t *testing.T) string {
	t.Helper()

	p, err := os.MkdirTemp("", "osv-scanner-test-*")
	if err != nil {
		t.Fatalf("could not create test directory: %v", err)
	}

	// ensure the test directory is removed when we're done testing
	t.Cleanup(func() {
		_ = os.RemoveAll(p)
	})

	return p
}
