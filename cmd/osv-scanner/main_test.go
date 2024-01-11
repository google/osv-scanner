// main cannot be accessed directly, so cannot use main_test
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/testutility"
)

func createTestDir(t *testing.T) (string, func()) {
	t.Helper()

	p, err := os.MkdirTemp("", "osv-scanner-test-*")
	if err != nil {
		t.Fatalf("could not create test directory: %v", err)
	}

	return p, func() {
		_ = os.RemoveAll(p)
	}
}

type cliTestCase struct {
	name         string
	args         []string
	wantExitCode int
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

	return strings.ReplaceAll(str, cwd, "<rootdir>")
}

// normalizeRootDirectory attempts to replace references to the temp directory
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

	return str
}

func testCli(t *testing.T, tc cliTestCase) {
	t.Helper()

	stdoutBuffer := &bytes.Buffer{}
	stderrBuffer := &bytes.Buffer{}

	ec := run(tc.args, stdoutBuffer, stderrBuffer)
	// ec := run(tc.args, os.Stdout, os.Stderr)

	stdout := normalizeErrors(t, normalizeTempDirectory(t, normalizeRootDirectory(t, normalizeFilePaths(t, stdoutBuffer.String()))))
	stderr := normalizeErrors(t, normalizeTempDirectory(t, normalizeRootDirectory(t, normalizeFilePaths(t, stderrBuffer.String()))))

	if ec != tc.wantExitCode {
		t.Errorf("cli exited with code %d, not %d", ec, tc.wantExitCode)
	}

	testutility.NewSnapshot().MatchText(t, stdout)
	testutility.NewSnapshot().MatchText(t, stderr)
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		{
			name:         "",
			args:         []string{""},
			wantExitCode: 128,
		},
		{
			name:         "",
			args:         []string{"", "--version"},
			wantExitCode: 0,
		},
		// one specific supported lockfile
		{
			name:         "one specific supported lockfile",
			args:         []string{"", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		// one specific supported sbom with vulns
		{
			name:         "folder of supported sbom with vulns",
			args:         []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/"},
			wantExitCode: 1,
		},
		// one specific supported sbom with vulns
		{
			name:         "one specific supported sbom with vulns",
			args:         []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			wantExitCode: 1,
		},
		// one specific unsupported lockfile
		{
			name:         "",
			args:         []string{"", "./fixtures/locks-many/not-a-lockfile.toml"},
			wantExitCode: 128,
		},
		// all supported lockfiles in the directory should be checked
		{
			name:         "Scan locks-many",
			args:         []string{"", "./fixtures/locks-many"},
			wantExitCode: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			name:         "all supported lockfiles in the directory should be checked",
			args:         []string{"", "./fixtures/locks-many-with-invalid"},
			wantExitCode: 127,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			name:         "only the files in the given directories are checked by default (no recursion)",
			args:         []string{"", "./fixtures/locks-one-with-nested"},
			wantExitCode: 0,
		},
		// nested directories are checked when `--recursive` is passed
		{
			name:         "nested directories are checked when `--recursive` is passed",
			args:         []string{"", "--recursive", "./fixtures/locks-one-with-nested"},
			wantExitCode: 0,
		},
		// .gitignored files
		{
			name:         "",
			args:         []string{"", "--recursive", "./fixtures/locks-gitignore"},
			wantExitCode: 0,
		},
		// ignoring .gitignore
		{
			name:         "",
			args:         []string{"", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			wantExitCode: 0,
		},
		// output with json
		{
			name:         "json output 1",
			args:         []string{"", "--json", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		{
			name:         "json output 2",
			args:         []string{"", "--format", "json", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		// output format: sarif
		{
			name:         "Empty sarif output",
			args:         []string{"", "--format", "sarif", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		{
			name:         "Sarif with vulns",
			args:         []string{"", "--format", "sarif", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			wantExitCode: 1,
		},
		// output format: gh-annotations
		{
			name:         "Empty gh-annotations output",
			args:         []string{"", "--format", "gh-annotations", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		{
			name:         "gh-annotations with vulns",
			args:         []string{"", "--format", "gh-annotations", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			wantExitCode: 1,
		},
		// output format: markdown table
		{
			name:         "",
			args:         []string{"", "--format", "markdown", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			wantExitCode: 1,
		},
		// output format: unsupported
		{
			name:         "",
			args:         []string{"", "--format", "unknown", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 127,
		},
		// one specific supported lockfile with ignore
		{
			name:         "one specific supported lockfile with ignore",
			args:         []string{"", "./fixtures/locks-test-ignore/package-lock.json"},
			wantExitCode: 0,
		},
		{
			name:         "invalid --verbosity value",
			args:         []string{"", "--verbosity", "unknown", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 127,
		},
		{
			name:         "verbosity level = error",
			args:         []string{"", "--verbosity", "error", "--format", "table", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		{
			name:         "verbosity level = info",
			args:         []string{"", "--verbosity", "info", "--format", "table", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}

func TestRun_LockfileWithExplicitParseAs(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		// unsupported parse-as
		{
			name:         "",
			args:         []string{"", "-L", "my-file:./fixtures/locks-many/composer.lock"},
			wantExitCode: 127,
		},
		// empty is default
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./fixtures/locks-many/composer.lock"),
			},
			wantExitCode: 0,
		},
		// empty works as an escape (no fixture because it's not valid on Windows)
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:file"),
			},
			wantExitCode: 127,
		},
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:project/package-lock.json"),
			},
			wantExitCode: 127,
		},
		// one lockfile with local path
		{
			name:         "one lockfile with local path",
			args:         []string{"", "--lockfile=go.mod:./fixtures/locks-many/replace-local.mod"},
			wantExitCode: 0,
		},
		// when an explicit parse-as is given, it's applied to that file
		{
			name: "",
			args: []string{
				"",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			wantExitCode: 1,
		},
		// multiple, + output order is deterministic
		{
			name: "",
			args: []string{
				"",
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			wantExitCode: 1,
		},
		{
			name: "",
			args: []string{
				"",
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			wantExitCode: 1,
		},
		// files that error on parsing stop parsable files from being checked
		{
			name: "",
			args: []string{
				"",
				"-L",
				"Cargo.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
				filepath.FromSlash("./fixtures/locks-many"),
			},
			wantExitCode: 127,
		},
		// parse-as takes priority, even if it's wrong
		{
			name: "",
			args: []string{
				"",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-many/yarn.lock"),
			},
			wantExitCode: 127,
		},
		// "apk-installed" is supported
		{
			name: "",
			args: []string{
				"",
				"-L",
				"apk-installed:" + filepath.FromSlash("./fixtures/locks-many/installed"),
			},
			wantExitCode: 0,
		},
		// "dpkg-status" is supported
		{
			name: "",
			args: []string{
				"",
				"-L",
				"dpkg-status:" + filepath.FromSlash("./fixtures/locks-many/status"),
			},
			wantExitCode: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}

// TestRun_GithubActions tests common actions the github actions reusable workflow will run
func TestRun_GithubActions(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		{
			name:         "scanning osv-scanner custom format",
			args:         []string{"", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json"},
			wantExitCode: 1,
		},
		{
			name:         "scanning osv-scanner custom format output json",
			args:         []string{"", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json", "--format=sarif"},
			wantExitCode: 1,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}

func TestRun_LocalDatabases(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		// one specific supported lockfile
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		// one specific supported sbom with vulns
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/postgres-stretch.cdx.xml"},
			wantExitCode: 1,
		},
		// one specific unsupported lockfile
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "./fixtures/locks-many/not-a-lockfile.toml"},
			wantExitCode: 128,
		},
		// all supported lockfiles in the directory should be checked
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "./fixtures/locks-many"},
			wantExitCode: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "./fixtures/locks-many-with-invalid"},
			wantExitCode: 127,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "./fixtures/locks-one-with-nested"},
			wantExitCode: 0,
		},
		// nested directories are checked when `--recursive` is passed
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "--recursive", "./fixtures/locks-one-with-nested"},
			wantExitCode: 0,
		},
		// .gitignored files
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "--recursive", "./fixtures/locks-gitignore"},
			wantExitCode: 0,
		},
		// ignoring .gitignore
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			wantExitCode: 0,
		},
		// output with json
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "--json", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "--format", "json", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
		// output format: markdown table
		{
			name:         "",
			args:         []string{"", "--experimental-local-db", "--format", "markdown", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testDir, cleanupTestDir := createTestDir(t)
			defer cleanupTestDir()

			old := tt.args

			tt.args = []string{"", "--experimental-local-db-path", testDir}
			tt.args = append(tt.args, old[1:]...)

			// run each test twice since they should provide the same output,
			// and the second run should be fast as the db is already available
			testCli(t, tt)
			testCli(t, tt)
		})
	}
}

func TestRun_Licenses(t *testing.T) {
	t.Parallel()
	tests := []cliTestCase{
		{
			name:         "No vulnerabilities with license summary",
			args:         []string{"", "--experimental-licenses-summary", "./fixtures/locks-many"},
			wantExitCode: 0,
		},
		{
			name:         "No vulnerabilities with license summary in markdown",
			args:         []string{"", "--experimental-licenses-summary", "--format=markdown", "./fixtures/locks-many"},
			wantExitCode: 0,
		},
		{
			name:         "Vulnerabilities and license summary",
			args:         []string{"", "--experimental-licenses-summary", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			wantExitCode: 1,
		},
		{
			name:         "Vulnerabilities and license violations with allowlist",
			args:         []string{"", "--experimental-licenses", "MIT", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			wantExitCode: 1,
		},
		{
			name:         "Vulnerabilities and all license violations allowlisted",
			args:         []string{"", "--experimental-licenses", "Apache-2.0", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			wantExitCode: 1,
		},
		{
			name:         "Some packages with license violations and show-all-packages in json",
			args:         []string{"", "--format=json", "--experimental-licenses", "MIT", "--experimental-all-packages", "./fixtures/locks-licenses/package-lock.json"},
			wantExitCode: 1,
		},
		{
			name:         "Some packages with license violations in json",
			args:         []string{"", "--format=json", "--experimental-licenses", "MIT", "./fixtures/locks-licenses/package-lock.json"},
			wantExitCode: 1,
		},
		{
			name:         "No license violations and show-all-packages in json",
			args:         []string{"", "--format=json", "--experimental-licenses", "MIT,Apache-2.0", "--experimental-all-packages", "./fixtures/locks-licenses/package-lock.json"},
			wantExitCode: 0,
		},
		{
			name:         "Licenses in summary mode json",
			args:         []string{"", "--format=json", "--experimental-licenses-summary", "./fixtures/locks-licenses/package-lock.json"},
			wantExitCode: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}
