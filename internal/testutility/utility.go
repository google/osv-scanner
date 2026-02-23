package testutility

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

// GetCurrentWorkingDirectory returns the current working directory, raising
// a fatal error if it cannot be retrieved for some reason
func GetCurrentWorkingDirectory(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}

	return dir
}

// applyWindowsReplacements will replace any matching strings if on Windows
func applyWindowsReplacements(content string, replacements map[string]string) string {
	if runtime.GOOS == "windows" {
		for match, replacement := range replacements {
			content = strings.ReplaceAll(content, match, replacement)
		}
	}

	return content
}

// CleanSnapshots ensures that snapshots are relevant and sorted for consistency
func CleanSnapshots(m *testing.M) {
	dirty, err := snaps.Clean(m, snaps.CleanOpts{Sort: true})

	if err != nil {
		fmt.Println("Error cleaning snaps:", err)
		os.Exit(1)
	}
	if dirty {
		fmt.Println("Some snapshots were outdated.")
		os.Exit(1)
	}
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

	runOnly, _, _ := strings.Cut(flag.Lookup("test.run").Value.String(), "/")
	runOnlyWithNoRegex := strings.Trim(runOnly, "^$")

	return runOnly == t.Name() || runOnlyWithNoRegex == t.Name()
}

// IsAcceptanceTesting returns true if the test suite is being run with acceptance tests enabled
func IsAcceptanceTesting() bool {
	return os.Getenv("TEST_ACCEPTANCE") == "true"
}

// SkipIfNotAcceptanceTesting marks the test as skipped unless the test suite is
// being run with acceptance tests enabled, as indicated by IsAcceptanceTesting,
// or the test is being run specifically with the -run flag
// This is used to skip tests that could require external dependencies other than go
func SkipIfNotAcceptanceTesting(t *testing.T, reason string) {
	t.Helper()

	if !IsAcceptanceTesting() && !isThisTestRunTarget(t) {
		Skip(t, "Skipping extended test: ", reason)
	}
}

// SkipIfShort marks the test as skipped if the short flag is set
// or the test is being run specifically with the -run flag
func SkipIfShort(t *testing.T) {
	t.Helper()

	if testing.Short() && !isThisTestRunTarget(t) {
		Skip(t, "Skipping long test: ", "Takes a while to run")
	}
}

func ValueIfOnWindows(win, or string) string {
	if runtime.GOOS == "windows" {
		return win
	}

	return or
}

func fixedLengthTempDir(parent string) (string, error) {
	n := rand.Int63n(1_000_000_000_000) //nolint:gosec // 10^12
	suffix := fmt.Sprintf("%0*d", 12, n)

	name := "osv-scanner-test-" + suffix
	path := filepath.Join(parent, name)

	return path, os.Mkdir(path, 0o700)
}

// CreateTestDir makes a temporary directory for use in testing that involves
// writing and reading files from disk, which is automatically cleaned up
// when testing finishes
func CreateTestDir(t *testing.T) string {
	t.Helper()

	p, err := fixedLengthTempDir(os.TempDir())
	if err != nil {
		t.Fatalf("could not create test directory: %v", err)
	}

	// ensure the test directory is removed when we're done testing
	t.Cleanup(func() {
		_ = os.RemoveAll(p)
	})

	return p
}
