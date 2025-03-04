// main cannot be accessed directly, so cannot use main_test
package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/urfave/cli/v2"
)

type cliTestCase struct {
	name string
	args []string
	exit int

	// replaceRules are only used for JSON output
	replaceRules []testutility.JSONReplaceRule
}

// muffledHandler eats certain log messages to reduce noise in the test output
type muffledWriter struct {
	*bytes.Buffer
}

func (m muffledWriter) Write(p []byte) (int, error) {
	// todo: work with the osv-scalibr team to see if we can reduce these
	for _, prefix := range []string{
		"Starting filesystem walk for root:",
		"End status: ",
		"Neither CPE nor PURL found for package",
		"Invalid PURL",
		"os-release[ID] not set, fallback to",
		"VERSION_ID not set in os-release",
		"osrelease.ParseOsRelease(): file does not exist",
	} {
		if bytes.HasPrefix(p, []byte(prefix)) {
			return len(p), nil
		}
	}

	return m.Buffer.Write(p)
}

func newMuffledWriter() muffledWriter {
	return muffledWriter{Buffer: &bytes.Buffer{}}
}

func runCli(t *testing.T, tc cliTestCase) (string, string) {
	t.Helper()

	stdout := newMuffledWriter()
	stderr := newMuffledWriter()

	ec := run(tc.args, stdout, stderr)

	if ec != tc.exit {
		t.Errorf("cli exited with code %d, not %d", ec, tc.exit)
	}

	return stdout.String(), stderr.String()
}

func testCli(t *testing.T, tc cliTestCase) {
	t.Helper()

	stdout, stderr := runCli(t, tc)

	testutility.NewSnapshot().MatchText(t, stdout)
	testutility.NewSnapshot().MatchText(t, stderr)
}

func testCliJSONWithCustomRules(t *testing.T, tc cliTestCase) {
	t.Helper()

	stdout, stderr := runCli(t, tc)

	testutility.NewSnapshot().MatchOSVScannerJSONOutput(t, stdout, tc.replaceRules...)
	testutility.NewSnapshot().MatchText(t, stderr)
}

func Test_run(t *testing.T) {
	tests := []cliTestCase{
		{
			name: "",
			args: []string{""},
			exit: 0,
		},
		{
			name: "version",
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
		// one specific supported sbom with vulns and invalid PURLs
		{
			name: "one specific supported sbom with invalid PURLs",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/bad-purls.cdx.xml"},
			exit: 0,
		},
		// one specific supported sbom with duplicate PURLs
		{
			name: "one specific supported sbom with duplicate PURLs",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/with-duplicates.cdx.xml"},
			exit: 1,
		},
		// one specific unsupported lockfile
		{
			name: "one specific unsupported lockfile",
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
			name: ".gitignored files",
			args: []string{"", "--recursive", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		// ignoring .gitignore
		{
			name: "ignoring .gitignore",
			args: []string{"", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		{
			name: "json output",
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
			name: "output format: markdown table",
			args: []string{"", "--format", "markdown", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		// output format: cyclonedx 1.4
		{
			name: "Empty cyclonedx 1.4 output",
			args: []string{"", "--format", "cyclonedx-1-4", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "cyclonedx 1.4 output",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "cyclonedx-1-4", "--all-packages", "./fixtures/locks-insecure"},
			exit: 1,
		},
		// output format: cyclonedx 1.5
		{
			name: "Empty cyclonedx 1.5 output",
			args: []string{"", "--format", "cyclonedx-1-5", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "cyclonedx 1.5 output",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "cyclonedx-1-5", "--all-packages", "./fixtures/locks-insecure"},
			exit: 1,
		},
		// output format: unsupported
		{
			name: "output format: unsupported",
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
		{
			name: "PURL SBOM case sensitivity (api)",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "table", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			exit: 1,
		},
		{
			name: "PURL SBOM case sensitivity (local)",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "--download-offline-databases", "--format", "table", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			exit: 1,
		},
		// Go project with an overridden go version
		{
			name: "Go project with an overridden go version",
			args: []string{"", "--config=./fixtures/go-project/go-version-config.toml", "./fixtures/go-project"},
			exit: 0,
		},
		// Go project with an overridden go version, recursive
		{
			name: "Go project with an overridden go version, recursive",
			args: []string{"", "--config=./fixtures/go-project/go-version-config.toml", "-r", "./fixtures/go-project"},
			exit: 0,
		},
		// broad config file that overrides a whole ecosystem
		{
			name: "config file can be broad",
			args: []string{"", "--config=./fixtures/osv-scanner-composite-config.toml", "--licenses=MIT", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json", "./fixtures/locks-many", "./fixtures/locks-insecure", "./fixtures/maven-transitive"},
			exit: 1,
		},
		// ignored vulnerabilities and packages without a reason should be called out
		{
			name: "ignores without reason should be explicitly called out",
			args: []string{"", "--config=./fixtures/osv-scanner-reasonless-ignores-config.toml", "./fixtures/locks-many/package-lock.json", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// invalid config file
		{
			name: "config file is invalid",
			args: []string{"", "./fixtures/config-invalid"},
			exit: 127,
		},
		// config file with unknown keys
		{
			name: "config files cannot have unknown keys",
			args: []string{"", "--config=./fixtures/osv-scanner-unknown-config.toml", "./fixtures/locks-many"},
			exit: 127,
		},
		// config file with multiple ignores with the same id
		{
			name: "config files should not have multiple ignores with the same id",
			args: []string{"", "--config=./fixtures/osv-scanner-duplicate-config.toml", "./fixtures/locks-many"},
			exit: 0,
		},
		// a bunch of requirements.txt files with different names
		{
			name: "requirements.txt can have all kinds of names",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-requirements"},
			exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCli(t, tt)
		})
	}
}

func Test_run_CallAnalysis(t *testing.T) {
	// Switch to acceptance test if this takes too long, or when we add rust tests
	// testutility.SkipIfNotAcceptanceTesting(t, "Takes a while to run")

	tests := []cliTestCase{
		{
			name: "Run with govulncheck",
			args: []string{"",
				"--call-analysis=go",
				"--config=./fixtures/osv-scanner-call-analysis-config.toml",
				"./fixtures/call-analysis-go-project"},
			exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCli(t, tt)
		})
	}
}

func Test_run_LockfileWithExplicitParseAs(t *testing.T) {
	tests := []cliTestCase{
		{
			name: "unsupported parse-as",
			args: []string{"", "-L", "my-file:./fixtures/locks-many/composer.lock"},
			exit: 127,
		},
		{
			name: "empty is default",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./fixtures/locks-many/composer.lock"),
			},
			exit: 0,
		},
		{
			name: "empty works as an escape (no fixture because it's not valid on Windows)",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:file"),
			},
			exit: 127,
		},
		{
			name: "empty works as an escape (no fixture because it's not valid on Windows)",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:project/package-lock.json"),
			},
			exit: 127,
		},
		{
			name: "one lockfile with local path",
			args: []string{"", "--lockfile=go.mod:./fixtures/locks-many/replace-local.mod"},
			exit: 0,
		},
		{
			name: "when an explicit parse-as is given, it's applied to that file",
			args: []string{
				"",
				"--config=./fixtures/osv-scanner-empty-config.toml",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			exit: 1,
		},
		{
			name: "multiple, + output order is deterministic",
			args: []string{
				"",
				"--config=./fixtures/osv-scanner-empty-config.toml",
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			exit: 1,
		},
		{
			name: "multiple, + output order is deterministic 2",
			args: []string{
				"",
				"--config=./fixtures/osv-scanner-empty-config.toml",
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			exit: 1,
		},
		{
			name: "files that error on parsing stop parsable files from being checked",
			args: []string{
				"",
				"-L",
				"Cargo.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
				filepath.FromSlash("./fixtures/locks-many"),
			},
			exit: 127,
		},
		{
			name: "parse-as takes priority, even if it's wrong",
			args: []string{
				"",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-many/yarn.lock"),
			},
			exit: 127,
		},
		{
			name: "\"apk-installed\" is supported",
			args: []string{
				"",
				"-L",
				"apk-installed:" + filepath.FromSlash("./fixtures/locks-many/installed"),
			},
			exit: 0,
		},
		{
			name: "\"dpkg-status\" is supported",
			args: []string{
				"",
				"-L",
				"dpkg-status:" + filepath.FromSlash("./fixtures/locks-many/status"),
			},
			exit: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr := runCli(t, tt)

			testutility.NewSnapshot().MatchText(t, stdout)
			testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
				"CreateFile": "stat",
			}).MatchText(t, stderr)
		})
	}
}

// Test_run_GithubActions tests common actions the github actions reusable workflow will run
func Test_run_GithubActions(t *testing.T) {
	tests := []cliTestCase{
		{
			name: "scanning osv-scanner custom format",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json"},
			exit: 1,
		},
		{
			name: "scanning osv-scanner custom format output json",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json", "--format=sarif"},
			exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCli(t, tt)
		})
	}
}

func Test_run_LocalDatabases(t *testing.T) {
	tests := []cliTestCase{
		{
			name: "one specific supported lockfile",
			args: []string{"", "--offline", "--download-offline-databases", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "one specific supported sbom with vulns",
			args: []string{"", "--offline", "--download-offline-databases", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/postgres-stretch.cdx.xml"},
			exit: 1,
		},
		{
			name: "one specific unsupported lockfile",
			args: []string{"", "--offline", "--download-offline-databases", "./fixtures/locks-many/not-a-lockfile.toml"},
			exit: 128,
		},
		{
			name: "all supported lockfiles in the directory should be checked",
			args: []string{"", "--offline", "--download-offline-databases", "./fixtures/locks-many"},
			exit: 0,
		},
		{
			name: "all supported lockfiles in the directory should be checked",
			args: []string{"", "--offline", "--download-offline-databases", "./fixtures/locks-many-with-invalid"},
			exit: 127,
		},
		{
			name: "only the files in the given directories are checked by default (no recursion)",
			args: []string{"", "--offline", "--download-offline-databases", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		{
			name: "nested directories are checked when `--recursive` is passed",
			args: []string{"", "--offline", "--download-offline-databases", "--recursive", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		{
			name: ".gitignored files",
			args: []string{"", "--offline", "--download-offline-databases", "--recursive", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		{
			name: "ignoring .gitignore",
			args: []string{"", "--offline", "--download-offline-databases", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		{
			name: "output with json",
			args: []string{"", "--offline", "--download-offline-databases", "--format", "json", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "output format: markdown table",
			args: []string{"", "--offline", "--download-offline-databases", "--format", "markdown", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "database should be downloaded only when offline is set",
			args: []string{"", "--download-offline-databases", "./fixtures/locks-many"},
			exit: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if testutility.IsAcceptanceTesting() {
				testDir := testutility.CreateTestDir(t)
				old := tt.args
				tt.args = []string{"", "--local-db-path", testDir}
				tt.args = append(tt.args, old[1:]...)
			}

			// run each test twice since they should provide the same output,
			// and the second run should be fast as the db is already available
			testCli(t, tt)
			testCli(t, tt)
		})
	}
}

func Test_run_LocalDatabases_AlwaysOffline(t *testing.T) {
	tests := []cliTestCase{
		{
			name: "a bunch of different lockfiles and ecosystem",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "./fixtures/locks-requirements", "./fixtures/locks-many"},
			exit: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := testutility.CreateTestDir(t)
			old := tt.args
			tt.args = []string{"", "--local-db-path", testDir}
			tt.args = append(tt.args, old[1:]...)

			// run each test twice since they should provide the same output,
			// and the second run should be fast as the db is already available
			testCli(t, tt)
			testCli(t, tt)
		})
	}
}

func Test_run_Licenses(t *testing.T) {
	tests := []cliTestCase{
		{
			name: "No vulnerabilities with license summary",
			args: []string{"", "--licenses", "./fixtures/locks-many"},
			exit: 0,
		},
		{
			name: "No vulnerabilities with license summary in markdown",
			args: []string{"", "--licenses", "--format=markdown", "./fixtures/locks-many"},
			exit: 0,
		},
		{
			name: "Vulnerabilities and license summary",
			args: []string{"", "--licenses", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		{
			name: "Vulnerabilities and license violations with allowlist",
			args: []string{"", "--licenses=MIT", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		{
			name: "Vulnerabilities and all license violations allowlisted",
			args: []string{"", "--licenses=Apache-2.0", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			exit: 1,
		},
		{
			name: "Some packages with license violations and show-all-packages in json",
			args: []string{"", "--format=json", "--licenses=MIT", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			exit: 1,
		},
		{
			name: "Some packages with ignored licenses",
			args: []string{"", "--config=./fixtures/osv-scanner-complex-licenses-config.toml", "--licenses=MIT", "./fixtures/locks-many", "./fixtures/locks-insecure"},
			exit: 1,
		},
		{
			name: "Some packages with license violations in json",
			args: []string{"", "--format=json", "--licenses=MIT", "./fixtures/locks-licenses/package-lock.json"},
			exit: 1,
		},
		{
			name: "No license violations and show-all-packages in json",
			args: []string{"", "--format=json", "--licenses=MIT,Apache-2.0", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			exit: 0,
		},
		{
			name: "Show all Packages with license summary in json",
			args: []string{"", "--format=json", "--licenses", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			exit: 0,
		},
		{
			name: "Licenses in summary mode json",
			args: []string{"", "--format=json", "--licenses", "./fixtures/locks-licenses/package-lock.json"},
			exit: 0,
		},
		{
			name: "Licenses with expressions",
			args: []string{"", "--config=./fixtures/osv-scanner-expressive-licenses-config.toml", "--licenses=MIT,BSD-3-Clause", "./fixtures/locks-licenses/package-lock.json"},
			exit: 1,
		},
		{
			name: "Licenses with invalid expression",
			args: []string{"", "--config=./fixtures/osv-scanner-invalid-licenses-config.toml", "--licenses=MIT,BSD-3-Clause", "./fixtures/locks-licenses/package-lock.json"},
			exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCli(t, tt)
		})
	}
}

func Test_run_Docker(t *testing.T) {
	testutility.SkipIfNotAcceptanceTesting(t, "Takes a long time to pull down images")

	tests := []cliTestCase{
		{
			name: "Fake alpine image",
			args: []string{"", "scan", "image", "alpine:non-existent-tag"},
			exit: 127,
		},
		{
			name: "Fake image entirely",
			args: []string{"", "scan", "image", "this-image-definitely-does-not-exist-abcde"},
			exit: 127,
		},
		// TODO: How to prevent these snapshots from changing constantly
		{
			name: "Real empty image",
			args: []string{"", "scan", "image", "hello-world"},
			exit: 128, // No packages found
		},
		{
			name: "Real empty image with tag",
			args: []string{"", "scan", "image", "hello-world:linux"},
			exit: 128, // No package found
		},
		{
			name: "Real Alpine image",
			args: []string{"", "scan", "image", "alpine:3.18.9"},
			exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only test on linux, and mac/windows CI/CD does not come with docker preinstalled
			if runtime.GOOS != "linux" {
				testutility.Skip(t, "Skipping Docker-based test as only Linux has Docker installed in CI")
			}

			testCli(t, tt)
		})
	}
}

func Test_run_OCIImage(t *testing.T) {
	testutility.SkipIfNotAcceptanceTesting(t, "Takes a while to run")

	tests := []cliTestCase{
		{
			name: "Invalid path",
			args: []string{"", "scan", "image", "--archive", "./fixtures/oci-image/no-file-here.tar"},
			exit: 127,
		},
		{
			name: "Alpine 3.10 image tar with 3.18 version file",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-alpine.tar"},
			exit: 1,
		},
		{
			name: "Scanning python image with some packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-python-full.tar"},
			exit: 1,
		},
		{
			name: "Scanning python image with no packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-python-empty.tar"},
			exit: 1,
		},
		{
			name: "Scanning java image with some packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-java-full.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using npm with no packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-node_modules-npm-empty.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using npm with some packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-node_modules-npm-full.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using yarn with no packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-node_modules-yarn-empty.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using yarn with some packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-node_modules-yarn-full.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using pnpm with no packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-node_modules-pnpm-empty.tar"},
			exit: 1,
		},
		{
			name: "scanning node_modules using pnpm with some packages",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-node_modules-pnpm-full.tar"},
			exit: 1,
		},
		{
			name: "scanning image with go binary",
			args: []string{"", "scan", "image", "--archive", "../../internal/image/fixtures/test-package-tracing.tar"},
			exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func Test_run_OCIImageAllPackagesJSON(t *testing.T) {
	testutility.SkipIfNotAcceptanceTesting(t, "Takes a while to run")

	if runtime.GOOS == "windows" {
		// Windows messes with the file paths to break the output
		testutility.Skip(t)
	}

	tests := []cliTestCase{
		{
			name: "Scanning python image with some packages",
			args: []string{"", "scan", "image", "--archive", "--format=json", "../../internal/image/fixtures/test-python-full.tar"},
			exit: 1,
			replaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
				testutility.ShortenHistoryCommandLength,
			},
		},
		{
			name: "scanning node_modules using npm with some packages",
			args: []string{"", "scan", "image", "--archive", "--format=json", "../../internal/image/fixtures/test-node_modules-npm-full.tar"},
			exit: 1,
			replaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
				testutility.ShortenHistoryCommandLength,
			},
		},
		{
			name: "scanning image with go binary",
			args: []string{"", "scan", "image", "--archive", "--all-packages", "--format=json", "../../internal/image/fixtures/test-go-binary.tar"},
			exit: 1,
			replaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// point out that we need the images to be built and saved separately
			for _, arg := range tt.args {
				if strings.HasPrefix(arg, "../../internal/image/fixtures/") && strings.HasSuffix(arg, ".tar") {
					if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s does not exist - have you run scripts/build_test_images.sh?", arg)
					}
				}
			}

			testCliJSONWithCustomRules(t, tt)
		})
	}
}

// Tests all subcommands here.
func Test_run_SubCommands(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			testCli(t, tt)
		})
	}
}

func Test_insertDefaultCommand(t *testing.T) {
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
			wantArgs:     []string{"", "default", "source", "file"},
		},
		// test when command is not specified
		{
			originalArgs: []string{"", "file"},
			wantArgs:     []string{"", "default", "source", "file"},
		},
		// test when command is also a filename
		{
			originalArgs: []string{"", "scan"}, // `scan` exists as a file on filesystem (`./cmd/osv-scanner/scan`)
			wantArgs:     []string{"", "scan"},
		},
		// test when subcommand is also a filename
		{
			originalArgs: []string{"", "default", "image"},
			wantArgs:     []string{"", "default", "image"},
		},
		// test when command is not valid
		{
			originalArgs: []string{"", "invalid"},
			wantArgs:     []string{"", "default", "source", "invalid"},
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
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}

		logger := cmdlogger.New(stdout, stderr)

		slog.SetDefault(slog.New(&logger))

		argsActual := insertDefaultCommand(tt.originalArgs, commands, defaultCommand, stderr)
		if !reflect.DeepEqual(argsActual, tt.wantArgs) {
			t.Errorf("Test Failed. Details:\n"+
				"Args (Got):  %s\n"+
				"Args (Want): %s\n", argsActual, tt.wantArgs)
		}
		testutility.NewSnapshot().MatchText(t, stdout.String())
		testutility.NewSnapshot().MatchText(t, stderr.String())
	}
}

func Test_run_MavenTransitive(t *testing.T) {
	tests := []cliTestCase{
		{
			name: "scans transitive dependencies for pom.xml by default",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/maven-transitive/pom.xml"},
			exit: 1,
		},
		{
			name: "scans transitive dependencies by specifying pom.xml",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/abc.xml"},
			exit: 1,
		},
		{
			name: "scans pom.xml with non UTF-8 encoding",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/encoding.xml"},
			exit: 1,
		},
		{
			// Direct dependencies do not have any vulnerability.
			name: "does not scan transitive dependencies for pom.xml with offline mode",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "--download-offline-databases", "./fixtures/maven-transitive/pom.xml"},
			exit: 0,
		},
		{
			// Direct dependencies do not have any vulnerability.
			name: "does not scan transitive dependencies for pom.xml with no-resolve",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--no-resolve", "./fixtures/maven-transitive/pom.xml"},
			exit: 0,
		},
		{
			name: "scans dependencies from multiple registries",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/registry.xml"},
			exit: 1,
		},
		{
			name: "resolve transitive dependencies with native data source",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--data-source=native", "-L", "pom.xml:./fixtures/maven-transitive/registry.xml"},
			exit: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCli(t, tt)
		})
	}
}

func Test_run_MoreLockfiles(t *testing.T) {
	tests := []cliTestCase{
		{
			name: "uv.lock",
			args: []string{"", "-L", "./fixtures/locks-scalibr/uv.lock"},
			exit: 0,
		},
		{
			name: "depsjson",
			args: []string{"", "-L", "deps.json:./fixtures/locks-scalibr/depsjson"},
			exit: 1,
		},
		{
			name: "cabal.project.freeze",
			args: []string{"", "-L", "./fixtures/locks-scalibr/cabal.project.freeze"},
			exit: 1,
		},
		{
			name: "stack.yaml.lock",
			args: []string{"", "-L", "./fixtures/locks-scalibr/stack.yaml.lock"},
			exit: 0,
		},
		/*
			{
				name: "Package.resolved",
				args: []string{"", "-L", "./fixtures/locks-scalibr/Package.resolved"},
				exit: 0,
			},
		*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCli(t, tt)
		})
	}
}
