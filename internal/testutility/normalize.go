package testutility

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
)

// normalizeFilePathsOnOutput tries to ensure lines in the given `output` are
// less than 250 characters by normalizing any file paths that are present
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

// normalizeFilePaths attempts to normalize any file paths in the given `output`
// so that they can be compared reliably regardless of the file path separator
// being used.
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

// removeUntestableLines remove some lines from the output that are not testable
func removeUntestableLines(t *testing.T, str string) string {
	t.Helper()

	replacer := regexp.MustCompile(`Image not found locally, pulling docker image .*\.\.\.\n`)
	str = replacer.ReplaceAllLiteralString(str, "")

	return str
}

// normalizeSnapshot applies a series of normalizes to the buffer from a std stream like stdout and stderr
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
