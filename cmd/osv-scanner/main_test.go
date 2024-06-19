// main cannot be accessed directly, so cannot use main_test
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/urfave/cli/v2"
)

type cliTestCase struct {
	name string
	args []string
	exit int
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

// normalizeStdStream applies a series of normalizes to the buffer from a std stream like stdout and stderr
func normalizeStdStream(t *testing.T, std *bytes.Buffer) string {
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

func runCli(t *testing.T, tc cliTestCase) (string, string) {
	t.Helper()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	ec := run(tc.args, stdout, stderr)

	if ec != tc.exit {
		t.Errorf("cli exited with code %d, not %d", ec, tc.exit)
	}

	return normalizeStdStream(t, stdout), normalizeStdStream(t, stderr)
}

func testCli(t *testing.T, tc cliTestCase) {
	t.Helper()

	stdout, stderr := runCli(t, tc)

	testutility.NewSnapshot().MatchText(t, stdout)
	testutility.NewSnapshot().MatchText(t, stderr)
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		{
			name: "",
			args: []string{""},
			exit: 128,
		},
		{
			name: "",
			args: []string{"", "--version"},
			exit: 0,
		},
		// one specific supported lockfile
		{
			name: "one specific supported lockfile",
			args: []string{"", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// one specific supported sbom with vulns
		{
			name: "folder of supported sbom with vulns",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/"},
			exit: 1,
		},
		// one specific supported sbom with vulns
		{
			name: "one specific supported sbom with vulns",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			exit: 1,
		},
		// one specific unsupported lockfile
		{
			name: "",
			args: []string{"", "./fixtures/locks-many/not-a-lockfile.toml"},
			exit: 128,
		},
		// all supported lockfiles in the directory should be checked
		{
			name: "Scan locks-many",
			args: []string{"", "./fixtures/locks-many"},
			exit: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			name: "all supported lockfiles in the directory should be checked",
			args: []string{"", "./fixtures/locks-many-with-invalid"},
			exit: 127,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			name: "only the files in the given directories are checked by default (no recursion)",
			args: []string{"", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		// nested directories are checked when `--recursive` is passed
		{
			name: "nested directories are checked when `--recursive` is passed",
			args: []string{"", "--recursive", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		// .gitignored files
		{
			name: "",
			args: []string{"", "--recursive", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		// ignoring .gitignore
		{
			name: "",
			args: []string{"", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		// output with json
		{
			name: "json output 1",
			args: []string{"", "--json", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "json output 2",
			args: []string{"", "--format", "json", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// output format: sarif
		{
			name: "Empty sarif output",
			args: []string{"", "--format", "sarif", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "Sarif with vulns",
			args: []string{"", "--format", "sarif", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		// output format: gh-annotations
		{
			name: "Empty gh-annotations output",
			args: []string{"", "--format", "gh-annotations", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "gh-annotations with vulns",
			args: []string{"", "--format", "gh-annotations", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		// output format: markdown table
		{
			name: "",
			args: []string{"", "--format", "markdown", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		// output format: unsupported
		{
			name: "",
			args: []string{"", "--format", "unknown", "./fixtures/locks-many/composer.lock"},
			exit: 127,
		},
		// one specific supported lockfile with ignore
		{
			name: "one specific supported lockfile with ignore",
			args: []string{"", "./fixtures/locks-test-ignore/package-lock.json"},
			exit: 0,
		},
		{
			name: "invalid --verbosity value",
			args: []string{"", "--verbosity", "unknown", "./fixtures/locks-many/composer.lock"},
			exit: 127,
		},
		{
			name: "verbosity level = error",
			args: []string{"", "--verbosity", "error", "--format", "table", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "verbosity level = info",
			args: []string{"", "--verbosity", "info", "--format", "table", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// Go project with an overridden go version
		{
			name: "Go project with an overridden go version",
			args: []string{"", "./fixtures/go-project"},
			exit: 0,
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

func TestRunCallAnalysis(t *testing.T) {
	t.Parallel()

	// Switch to acceptance test if this takes too long, or when we add rust tests
	// testutility.SkipIfNotAcceptanceTesting(t, "Takes a while to run")

	tests := []cliTestCase{
		{
			name: "Run with govulncheck",
			args: []string{"",
				"--call-analysis=go",
				"--config=./fixtures/osv-scanner-empty-config.toml",
				"./fixtures/call-analysis-go-project"},
			exit: 1,
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
			name: "",
			args: []string{"", "-L", "my-file:./fixtures/locks-many/composer.lock"},
			exit: 127,
		},
		// empty is default
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./fixtures/locks-many/composer.lock"),
			},
			exit: 0,
		},
		// empty works as an escape (no fixture because it's not valid on Windows)
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:file"),
			},
			exit: 127,
		},
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:project/package-lock.json"),
			},
			exit: 127,
		},
		// one lockfile with local path
		{
			name: "one lockfile with local path",
			args: []string{"", "--lockfile=go.mod:./fixtures/locks-many/replace-local.mod"},
			exit: 0,
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
			exit: 1,
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
			exit: 1,
		},
		{
			name: "",
			args: []string{
				"",
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			exit: 1,
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
			exit: 127,
		},
		// parse-as takes priority, even if it's wrong
		{
			name: "",
			args: []string{
				"",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-many/yarn.lock"),
			},
			exit: 127,
		},
		// "apk-installed" is supported
		{
			name: "",
			args: []string{
				"",
				"-L",
				"apk-installed:" + filepath.FromSlash("./fixtures/locks-many/installed"),
			},
			exit: 0,
		},
		// "dpkg-status" is supported
		{
			name: "",
			args: []string{
				"",
				"-L",
				"dpkg-status:" + filepath.FromSlash("./fixtures/locks-many/status"),
			},
			exit: 0,
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
			name: "scanning osv-scanner custom format",
			args: []string{"", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json"},
			exit: 1,
		},
		{
			name: "scanning osv-scanner custom format output json",
			args: []string{"", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json", "--format=sarif"},
			exit: 1,
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
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// one specific supported sbom with vulns
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/postgres-stretch.cdx.xml"},
			exit: 1,
		},
		// one specific unsupported lockfile
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "./fixtures/locks-many/not-a-lockfile.toml"},
			exit: 128,
		},
		// all supported lockfiles in the directory should be checked
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "./fixtures/locks-many"},
			exit: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "./fixtures/locks-many-with-invalid"},
			exit: 127,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		// nested directories are checked when `--recursive` is passed
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "--recursive", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		// .gitignored files
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "--recursive", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		// ignoring .gitignore
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		// output with json
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "--json", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "--format", "json", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// output format: markdown table
		{
			name: "",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "--format", "markdown", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// database should be downloaded only when offline is set
		{
			name: "",
			args: []string{"", "--experimental-download-offline-databases", "./fixtures/locks-many"},
			exit: 127,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if testutility.IsAcceptanceTest() {
				testDir := testutility.CreateTestDir(t)
				old := tt.args
				tt.args = []string{"", "--experimental-local-db-path", testDir}
				tt.args = append(tt.args, old[1:]...)
			}

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
			name: "No vulnerabilities with license summary",
			args: []string{"", "--experimental-licenses-summary", "./fixtures/locks-many"},
			exit: 0,
		},
		{
			name: "No vulnerabilities with license summary in markdown",
			args: []string{"", "--experimental-licenses-summary", "--format=markdown", "./fixtures/locks-many"},
			exit: 0,
		},
		{
			name: "Vulnerabilities and license summary",
			args: []string{"", "--experimental-licenses-summary", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		{
			name: "Vulnerabilities and license violations with allowlist",
			args: []string{"", "--experimental-licenses", "MIT", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		{
			name: "Vulnerabilities and all license violations allowlisted",
			args: []string{"", "--experimental-licenses", "Apache-2.0", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		{
			name: "Some packages with license violations and show-all-packages in json",
			args: []string{"", "--format=json", "--experimental-licenses", "MIT", "--experimental-all-packages", "./fixtures/locks-licenses/package-lock.json"},
			exit: 1,
		},
		{
			name: "Some packages with license violations in json",
			args: []string{"", "--format=json", "--experimental-licenses", "MIT", "./fixtures/locks-licenses/package-lock.json"},
			exit: 1,
		},
		{
			name: "No license violations and show-all-packages in json",
			args: []string{"", "--format=json", "--experimental-licenses", "MIT,Apache-2.0", "--experimental-all-packages", "./fixtures/locks-licenses/package-lock.json"},
			exit: 0,
		},
		{
			name: "Licenses in summary mode json",
			args: []string{"", "--format=json", "--experimental-licenses-summary", "./fixtures/locks-licenses/package-lock.json"},
			exit: 0,
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

func TestRun_OCIImage(t *testing.T) {
	t.Parallel()

	testutility.SkipIfNotAcceptanceTesting(t, "Not consistent on MacOS/Windows")

	tests := []cliTestCase{
		{
			name: "Invalid path",
			args: []string{"", "--experimental-oci-image", "./fixtures/oci-image/no-file-here.tar"},
			exit: 127,
		},
		{
			name: "Alpine 3.10 image tar with 3.18 version file",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-alpine.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using npm with no packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-npm-empty.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using npm with some packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-npm-full.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using yarn with no packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-yarn-empty.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using yarn with some packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-yarn-full.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using pnpm with no packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-pnpm-empty.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using pnpm with some packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-pnpm-full.tar"},
			exit: 1,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// point out that we need the images to be built and saved separately
			for _, arg := range tt.args {
				if strings.HasPrefix(arg, "../../internal/image/fixtures/") && strings.HasSuffix(arg, ".tar") {
					if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s does not exist - have you run scripts/build_test_images.sh?", arg)
					}
				}
			}

			testCli(t, tt)
		})
	}
}

// Tests all subcommands here.
func TestRun_SubCommands(t *testing.T) {
	t.Parallel()
	tests := []cliTestCase{
		// without subcommands
		{
			name: "with no subcommand",
			args: []string{"", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// with scan subcommand
		{
			name: "with scan subcommand",
			args: []string{"", "scan", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// scan with a flag
		{
			name: "scan with a flag",
			args: []string{"", "scan", "--recursive", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		// TODO: add tests for other future subcommands
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}

func TestRun_InsertDefaultCommand(t *testing.T) {
	t.Parallel()
	commands := []*cli.Command{
		{Name: "default"},
		{Name: "scan"},
	}
	defaultCommand := "default"

	tests := []struct {
		originalArgs []string
		wantArgs     []string
	}{
		// test when default command is specified
		{
			originalArgs: []string{"", "default", "file"},
			wantArgs:     []string{"", "default", "file"},
		},
		// test when command is not specified
		{
			originalArgs: []string{"", "file"},
			wantArgs:     []string{"", "default", "file"},
		},
		// test when command is also a filename
		{
			originalArgs: []string{"", "scan"}, // `scan` exists as a file on filesystem (`./cmd/osv-scanner/scan`)
			wantArgs:     []string{"", "scan"},
		},
		// test when command is not valid
		{
			originalArgs: []string{"", "invalid"},
			wantArgs:     []string{"", "default", "invalid"},
		},
		// test when command is a built-in option
		{
			originalArgs: []string{"", "--version"},
			wantArgs:     []string{"", "--version"},
		},
		{
			originalArgs: []string{"", "-h"},
			wantArgs:     []string{"", "-h"},
		},
		{
			originalArgs: []string{"", "help"},
			wantArgs:     []string{"", "help"},
		},
	}

	for _, tt := range tests {
		tt := tt
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		argsActual := insertDefaultCommand(tt.originalArgs, commands, defaultCommand, stdout, stderr)
		if !reflect.DeepEqual(argsActual, tt.wantArgs) {
			t.Errorf("Test Failed. Details:\n"+
				"Args (Got):  %s\n"+
				"Args (Want): %s\n", argsActual, tt.wantArgs)
		}
		testutility.NewSnapshot().MatchText(t, normalizeStdStream(t, stdout))
		testutility.NewSnapshot().MatchText(t, normalizeStdStream(t, stderr))
	}
}

func TestRun_MavenTransitive(t *testing.T) {
	t.Parallel()
	tests := []cliTestCase{
		{
			name: "scans transitive dependencies for pom.xml by default",
			args: []string{"", "./fixtures/maven-transitive/pom.xml"},
			exit: 1,
		},
		{
			name: "scans transitive dependencies by specifying pom.xml",
			args: []string{"", "-L", "pom.xml:./fixtures/maven-transitive/abc.xml"},
			exit: 1,
		},
		{
			// Direct dependencies do not have any vulnerability.
			name: "does not scan transitive dependencies for pom.xml with offline mode",
			args: []string{"", "--experimental-offline", "--experimental-download-offline-databases", "./fixtures/maven-transitive/pom.xml"},
			exit: 0,
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
