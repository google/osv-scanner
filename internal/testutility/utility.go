package testutility

import (
	"bufio"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	//nolint: depguard // We need regexp for the QuoteMeta function
	"regexp"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/osv-scanner/v2/internal/cachedregexp"
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

// Only apply file path normalization to lines greater than 250
func normalizeFilePathsOnOutput(t *testing.T, output string) string {
	t.Helper()

	builder := strings.Builder{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) <= 250 {
			text = normalizeFilePaths(t, text)
		}

		// Always replace \\ because it could be in a long SARIF/JSON output
		text = strings.ReplaceAll(text, "\\\\", "/")
		builder.WriteString(text)
		builder.WriteString("\n")
	}

	// Match ending new line
	if strings.HasSuffix(output, "\n") {
		return builder.String()
	}

	return strings.TrimSuffix(builder.String(), "\n")
}

// Attempts to normalize any file paths in the given `output` so that they can
// be compared reliably regardless of the file path separator being used.
//
// Namely, escaped forward slashes are replaced with backslashes.
func normalizeFilePaths(t *testing.T, output string) string {
	t.Helper()
	return strings.ReplaceAll(strings.ReplaceAll(output, "\\\\", "/"), "\\", "/")
}

// normalizeRootDirectory attempts to replace references to the current working
// directory with "<rootdir>", in order to reduce the noise of the cmp diff
func normalizeRootDirectory(t *testing.T, str string) string {
	t.Helper()

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("could not get cwd (%v) - results and diff might be inaccurate!", err)
	}

	cwd = normalizeFilePaths(t, cwd)

	// file uris with Windows end up with three slashes, so we normalize that too
	str = strings.ReplaceAll(str, "file:///"+cwd, "file://<rootdir>")
	str = strings.ReplaceAll(str, cwd, "<rootdir>")

	// Replace versions without the root as well
	var root string
	if runtime.GOOS == "windows" {
		root = filepath.VolumeName(cwd) + "\\"
	}

	if strings.HasPrefix(cwd, "/") {
		root = "/"
	}
	str = strings.ReplaceAll(str, cwd[len(root):], "<rootdir>")

	return str
}

// normalizeUserCacheDirectory attempts to replace references to the current working
// directory with "<tempdir>", in order to reduce the noise of the cmp diff
func normalizeUserCacheDirectory(t *testing.T, str string) string {
	t.Helper()

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Errorf("could not get user cache (%v) - results and diff might be inaccurate!", err)
	}

	cacheDir = normalizeFilePaths(t, cacheDir)

	// file uris with Windows end up with three slashes, so we normalize that too
	str = strings.ReplaceAll(str, "file:///"+cacheDir, "file://<tempdir>")

	return strings.ReplaceAll(str, cacheDir, "<tempdir>")
}

// normalizeTempDirectory attempts to replace references to the temp directory
// with "<tempdir>", to ensure tests pass across different OSs
func normalizeTempDirectory(t *testing.T, str string) string {
	t.Helper()

	//nolint:gocritic // ensure that the directory doesn't end with a trailing slash
	tempDir := normalizeFilePaths(t, filepath.Join(os.TempDir()))
	re := cachedregexp.MustCompile(regexp.QuoteMeta(tempDir+`/osv-scanner-test-`) + `\d+`)

	return re.ReplaceAllString(str, "<tempdir>")
}

// normalizeErrors attempts to replace error messages on alternative OSs with their
// known linux equivalents, to ensure tests pass across different OSs
func normalizeErrors(t *testing.T, str string) string {
	t.Helper()

	str = strings.ReplaceAll(str, "The filename, directory name, or volume label syntax is incorrect.", "no such file or directory")
	str = strings.ReplaceAll(str, "The system cannot find the path specified.", "no such file or directory")
	str = strings.ReplaceAll(str, "The system cannot find the file specified.", "no such file or directory")

	return str
}

func removeUntestableLines(t *testing.T, str string) string {
	t.Helper()

	replacer := regexp.MustCompile(`Image not found locally, pulling docker image .*\.\.\.\n`)
	str = replacer.ReplaceAllLiteralString(str, "")

	return str
}

// normalizeStdStream applies a series of normalizes to the buffer from a std stream like stdout and stderr
func normalizeSnapshot(t *testing.T, str string) string {
	t.Helper()

	for _, normalizer := range []func(t *testing.T, str string) string{
		normalizeFilePathsOnOutput,
		normalizeRootDirectory,
		normalizeTempDirectory,
		normalizeUserCacheDirectory,
		normalizeErrors,
		removeUntestableLines,
	} {
		str = normalizer(t, str)
	}

	return str
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

	//nolint:usetesting // we need to customize the directory name to replace in snapshots
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
