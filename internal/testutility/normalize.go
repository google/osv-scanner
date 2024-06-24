package testutility

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/cachedregexp"
)

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

	return strings.ReplaceAll(str, cwd, "<rootdir>")
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
	re := cachedregexp.MustCompile(tempDir + `/osv-scanner-test-\d+`)

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

// NormalizeStdStream applies a series of normalizes to the buffer from a std stream like stdout and stderr
func NormalizeStdStream(t *testing.T, std *bytes.Buffer) string {
	t.Helper()

	str := std.String()

	for _, normalizer := range []func(t *testing.T, str string) string{
		normalizeFilePaths,
		normalizeRootDirectory,
		normalizeTempDirectory,
		normalizeUserCacheDirectory,
		normalizeErrors,
	} {
		str = normalizer(t, str)
	}

	return str
}

// NormalizeJSON applies a series of normalizes to a buffer after being marshalled as JSON
func NormalizeJSON(t *testing.T, data any) string {
	t.Helper()

	j, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}

	return NormalizeStdStream(t, bytes.NewBuffer(j))
}
