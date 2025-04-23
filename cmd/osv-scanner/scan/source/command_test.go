package source_test

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestCommand(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		// one specific supported lockfile
		{
			Name: "one specific supported lockfile",
			Args: []string{"", "scan", "source", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// one specific supported sbom with vulns
		{
			Name: "folder of supported sbom with vulns",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/"},
			Exit: 1,
		},
		// one specific supported sbom with vulns
		{
			Name: "one specific supported sbom with vulns",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		// one specific supported sbom with vulns and invalid PURLs
		{
			Name: "one specific supported sbom with invalid PURLs",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/bad-purls.cdx.xml"},
			Exit: 0,
		},
		// one specific supported sbom with duplicate PURLs
		{
			Name: "one specific supported sbom with duplicate PURLs",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/with-duplicates.cdx.xml"},
			Exit: 1,
		},
		// one file that does not match the supported sbom file names
		{
			Name: "one file that does not match the supported sbom file names",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/locks-many/composer.lock"},
			Exit: 127,
		},
		// one specific unsupported lockfile
		{
			Name: "one specific unsupported lockfile",
			Args: []string{"", "scan", "source", "./fixtures/locks-many/not-a-lockfile.toml"},
			Exit: 128,
		},
		// all supported lockfiles in the directory should be checked
		{
			Name: "Scan locks-many",
			Args: []string{"", "scan", "source", "./fixtures/locks-many"},
			Exit: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			Name: "all supported lockfiles in the directory should be checked",
			Args: []string{"", "scan", "source", "./fixtures/locks-many-with-invalid"},
			Exit: 127,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			Name: "only the files in the given directories are checked by default (no recursion)",
			Args: []string{"", "scan", "source", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		// nested directories are checked when `--recursive` is passed
		{
			Name: "nested directories are checked when `--recursive` is passed",
			Args: []string{"", "scan", "source", "--recursive", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		// .gitignored files
		{
			Name: ".gitignored files",
			Args: []string{"", "scan", "source", "--recursive", "./fixtures/locks-gitignore"},
			Exit: 0,
		},
		// ignoring .gitignore
		{
			Name: "ignoring .gitignore",
			Args: []string{"", "scan", "source", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			Exit: 0,
		},
		{
			Name: "json output",
			Args: []string{"", "scan", "source", "--format", "json", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// output format: sarif
		{
			Name: "Empty sarif output",
			Args: []string{"", "scan", "source", "--format", "sarif", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "Sarif with vulns",
			Args: []string{"", "scan", "source", "--format", "sarif", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		// output format: gh-annotations
		{
			Name: "Empty gh-annotations output",
			Args: []string{"", "scan", "source", "--format", "gh-annotations", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "gh-annotations with vulns",
			Args: []string{"", "scan", "source", "--format", "gh-annotations", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		// output format: markdown table
		{
			Name: "output format: markdown table",
			Args: []string{"", "scan", "source", "--format", "markdown", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		// output format: cyclonedx 1.4
		{
			Name: "Empty cyclonedx 1.4 output",
			Args: []string{"", "scan", "source", "--format", "cyclonedx-1-4", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "cyclonedx 1.4 output",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "cyclonedx-1-4", "--all-packages", "./fixtures/locks-insecure"},
			Exit: 1,
		},
		// output format: cyclonedx 1.5
		{
			Name: "Empty cyclonedx 1.5 output",
			Args: []string{"", "scan", "source", "--format", "cyclonedx-1-5", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "cyclonedx 1.5 output",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "cyclonedx-1-5", "--all-packages", "./fixtures/locks-insecure"},
			Exit: 1,
		},
		// output format: unsupported
		{
			Name: "output format: unsupported",
			Args: []string{"", "scan", "source", "--format", "unknown", "./fixtures/locks-many/composer.lock"},
			Exit: 127,
		},
		// one specific supported lockfile with ignore
		{
			Name: "one specific supported lockfile with ignore",
			Args: []string{"", "scan", "source", "./fixtures/locks-test-ignore/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "invalid --verbosity value",
			Args: []string{"", "scan", "source", "--verbosity", "unknown", "./fixtures/locks-many/composer.lock"},
			Exit: 127,
		},
		{
			Name: "verbosity level = error",
			Args: []string{"", "scan", "source", "--verbosity", "error", "--format", "table", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "verbosity level = info",
			Args: []string{"", "scan", "source", "--verbosity", "info", "--format", "table", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "PURL SBOM case sensitivity (api)",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "table", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "PURL SBOM case sensitivity (local)",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "--download-offline-databases", "--format", "table", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		// Go project with an overridden go version
		{
			Name: "Go project with an overridden go version",
			Args: []string{"", "scan", "source", "--config=./fixtures/go-project/go-version-config.toml", "./fixtures/go-project"},
			Exit: 0,
		},
		// Go project with an overridden go version, recursive
		{
			Name: "Go project with an overridden go version, recursive",
			Args: []string{"", "scan", "source", "--config=./fixtures/go-project/go-version-config.toml", "-r", "./fixtures/go-project"},
			Exit: 0,
		},
		// broad config file that overrides a whole ecosystem
		{
			Name: "config file can be broad",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-composite-config.toml", "--licenses=MIT", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json", "./fixtures/locks-many", "./fixtures/locks-insecure", "./fixtures/maven-transitive"},
			Exit: 1,
		},
		// ignored vulnerabilities and packages without a reason should be called out
		{
			Name: "ignores without reason should be explicitly called out",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-reasonless-ignores-config.toml", "./fixtures/locks-many/package-lock.json", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// invalid config file
		{
			Name: "config file is invalid",
			Args: []string{"", "scan", "source", "./fixtures/config-invalid"},
			Exit: 127,
		},
		// config file with unknown keys
		{
			Name: "config files cannot have unknown keys",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-unknown-config.toml", "./fixtures/locks-many"},
			Exit: 127,
		},
		// config file with multiple ignores with the same id
		{
			Name: "config files should not have multiple ignores with the same id",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-duplicate-config.toml", "./fixtures/locks-many"},
			Exit: 0,
		},
		// a bunch of requirements.txt files with different names
		{
			Name: "requirements.txt can have all kinds of names",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-requirements"},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_CallAnalysis(t *testing.T) {
	t.Parallel()

	// Switch to acceptance test if this takes too long, or when we add rust tests
	// testutility.SkipIfNotAcceptanceTesting(t, "Takes a while to run")

	tests := []testcmd.Case{
		{
			Name: "Run with govulncheck",
			Args: []string{"", "scan", "source",
				"--call-analysis=go",
				"--config=./fixtures/osv-scanner-call-analysis-config.toml",
				"./fixtures/call-analysis-go-project"},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_LockfileWithExplicitParseAs(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "unsupported parse-as",
			Args: []string{"", "scan", "source", "-L", "my-file:./fixtures/locks-many/composer.lock"},
			Exit: 127,
		},
		{
			Name: "empty is default",
			Args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./fixtures/locks-many/composer.lock"),
			},
			Exit: 0,
		},
		{
			Name: "empty works as an escape (no fixture because it's not valid on Windows)",
			Args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:file"),
			},
			Exit: 127,
		},
		{
			Name: "empty works as an escape (no fixture because it's not valid on Windows)",
			Args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:project/package-lock.json"),
			},
			Exit: 127,
		},
		{
			Name: "one lockfile with local path",
			Args: []string{"", "scan", "source", "--lockfile=go.mod:./fixtures/locks-many/replace-local.mod"},
			Exit: 0,
		},
		{
			Name: "when an explicit parse-as is given, it's applied to that file",
			Args: []string{
				"",
				"--config=./fixtures/osv-scanner-empty-config.toml",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			Exit: 1,
		},
		{
			Name: "multiple, + output order is deterministic",
			Args: []string{
				"",
				"--config=./fixtures/osv-scanner-empty-config.toml",
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			Exit: 1,
		},
		{
			Name: "multiple, + output order is deterministic 2",
			Args: []string{
				"",
				"--config=./fixtures/osv-scanner-empty-config.toml",
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			Exit: 1,
		},
		{
			Name: "files that error on parsing stop parsable files from being checked",
			Args: []string{
				"",
				"-L",
				"Cargo.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
				filepath.FromSlash("./fixtures/locks-many"),
			},
			Exit: 127,
		},
		{
			Name: "parse-as takes priority, even if it's wrong",
			Args: []string{
				"",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-many/yarn.lock"),
			},
			Exit: 127,
		},
		{
			Name: "\"apk-installed\" is supported",
			Args: []string{
				"",
				"-L",
				"apk-installed:" + filepath.FromSlash("./fixtures/locks-many/installed"),
			},
			Exit: 0,
		},
		{
			Name: "\"dpkg-status\" is supported",
			Args: []string{
				"",
				"-L",
				"dpkg-status:" + filepath.FromSlash("./fixtures/locks-many/status"),
			},
			Exit: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

// TestCommand_GithubActions tests common actions the github actions reusable workflow will run
func TestCommand_GithubActions(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "scanning osv-scanner custom format",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json"},
			Exit: 1,
		},
		{
			Name: "scanning osv-scanner custom format output json",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json", "--format=sarif"},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_LocalDatabases(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "one specific supported lockfile",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "one specific supported sbom with vulns",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/postgres-stretch.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "one specific unsupported lockfile",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "./fixtures/locks-many/not-a-lockfile.toml"},
			Exit: 128,
		},
		{
			Name: "all supported lockfiles in the directory should be checked",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "./fixtures/locks-many"},
			Exit: 0,
		},
		{
			Name: "all supported lockfiles in the directory should be checked",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "./fixtures/locks-many-with-invalid"},
			Exit: 127,
		},
		{
			Name: "only the files in the given directories are checked by default (no recursion)",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "nested directories are checked when `--recursive` is passed",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "--recursive", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: ".gitignored files",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "--recursive", "./fixtures/locks-gitignore"},
			Exit: 0,
		},
		{
			Name: "ignoring .gitignore",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			Exit: 0,
		},
		{
			Name: "output with json",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "--format", "json", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "output format: markdown table",
			Args: []string{"", "scan", "source", "--offline", "--download-offline-databases", "--format", "markdown", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "database should be downloaded only when offline is set",
			Args: []string{"", "scan", "source", "--download-offline-databases", "./fixtures/locks-many"},
			Exit: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			if testutility.IsAcceptanceTesting() {
				testDir := testutility.CreateTestDir(t)
				old := tt.Args
				tt.Args = []string{"", "scan", "source", "--local-db-path", testDir}
				tt.Args = append(tt.Args, old[3:]...)
			}

			// run each test twice since they should provide the same output,
			// and the second run should be fast as the db is already available
			testcmd.RunAndMatchSnapshots(t, tt)
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_LocalDatabases_AlwaysOffline(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "a bunch of different lockfiles and ecosystem",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "./fixtures/locks-requirements", "./fixtures/locks-many"},
			Exit: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testDir := testutility.CreateTestDir(t)
			old := tt.Args
			tt.Args = []string{"", "scan", "source", "--local-db-path", testDir}
			tt.Args = append(tt.Args, old[3:]...)

			// run each test twice since they should provide the same output,
			// and the second run should be fast as the db is already available
			testcmd.RunAndMatchSnapshots(t, tt)
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_Licenses(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "No vulnerabilities with license summary",
			Args: []string{"", "scan", "source", "--licenses", "./fixtures/locks-many"},
			Exit: 0,
		},
		{
			Name: "No vulnerabilities with license summary in markdown",
			Args: []string{"", "scan", "source", "--licenses", "--format=markdown", "./fixtures/locks-many"},
			Exit: 0,
		},
		{
			Name: "Vulnerabilities and license summary",
			Args: []string{"", "scan", "source", "--licenses", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Vulnerabilities and license violations with allowlist",
			Args: []string{"", "scan", "source", "--licenses=MIT", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Vulnerabilities and all license violations allowlisted",
			Args: []string{"", "scan", "source", "--licenses=Apache-2.0", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Some packages with license violations and show-all-packages in json",
			Args: []string{"", "scan", "source", "--format=json", "--licenses=MIT", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Some packages with ignored licenses",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-complex-licenses-config.toml", "--licenses=MIT", "./fixtures/locks-many", "./fixtures/locks-insecure"},
			Exit: 1,
		},
		{
			Name: "Some packages with license violations in json",
			Args: []string{"", "scan", "source", "--format=json", "--licenses=MIT", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "No license violations and show-all-packages in json",
			Args: []string{"", "scan", "source", "--format=json", "--licenses=MIT,Apache-2.0", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Show all Packages with license summary in json",
			Args: []string{"", "scan", "source", "--format=json", "--licenses", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Licenses in summary mode json",
			Args: []string{"", "scan", "source", "--format=json", "--licenses", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Licenses with expressions",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-expressive-licenses-config.toml", "--licenses=MIT,BSD-3-Clause", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Licenses with invalid expression",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-invalid-licenses-config.toml", "--licenses=MIT,BSD-3-Clause", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_MavenTransitive(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "scans transitive dependencies for pom.xml by default",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/maven-transitive/pom.xml"},
			Exit: 1,
		},
		{
			Name: "scans transitive dependencies by specifying pom.xml",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/abc.xml"},
			Exit: 1,
		},
		{
			Name: "scans pom.xml with non UTF-8 encoding",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/encoding.xml"},
			Exit: 1,
		},
		{
			// Direct dependencies do not have any vulnerability.
			Name: "does not scan transitive dependencies for pom.xml with offline mode",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "--download-offline-databases", "./fixtures/maven-transitive/pom.xml"},
			Exit: 0,
		},
		{
			// Direct dependencies do not have any vulnerability.
			Name: "does not scan transitive dependencies for pom.xml with no-resolve",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--no-resolve", "./fixtures/maven-transitive/pom.xml"},
			Exit: 0,
		},
		{
			Name: "scans dependencies from multiple registries",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/registry.xml"},
			Exit: 1,
		},
		{
			Name: "resolve transitive dependencies with native data source",
			Args: []string{"", "scan", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--data-source=native", "-L", "pom.xml:./fixtures/maven-transitive/registry.xml"},
			Exit: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_MoreLockfiles(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "uv.lock",
			Args: []string{"", "scan", "source", "-L", "./fixtures/locks-scalibr/uv.lock"},
			Exit: 0,
		},
		{
			Name: "depsjson",
			Args: []string{"", "scan", "source", "-L", "deps.json:./fixtures/locks-scalibr/depsjson"},
			Exit: 1,
		},
		{
			Name: "cabal.project.freeze",
			Args: []string{"", "scan", "source", "-L", "./fixtures/locks-scalibr/cabal.project.freeze"},
			Exit: 1,
		},
		{
			Name: "stack.yaml.lock",
			Args: []string{"", "scan", "source", "-L", "./fixtures/locks-scalibr/stack.yaml.lock"},
			Exit: 0,
		},
		{
			Name: "packages.config",
			Args: []string{"", "scan", "source", "-L", "./fixtures/locks-scalibr/packages.config"},
			Exit: 0,
		},
		{
			Name: "packages.lock.json",
			Args: []string{"", "scan", "source", "-L", "./fixtures/locks-scalibr/packages.lock.json"},
			Exit: 0,
		},
		/*
			{
				name: "Package.resolved",
				args: []string{"", "scan", "source", "-L", "./fixtures/locks-scalibr/Package.resolved"},
				exit: 0,
			},
		*/
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}
