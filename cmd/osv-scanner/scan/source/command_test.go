package source_test

import (
	"os"
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
			Args: []string{"", "source", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// one specific supported lockfile, explicitly not offline
		{
			Name: "one specific supported lockfile with offline explicitly false",
			Args: []string{"", "source", "--offline=false", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// one specific supported sbom with vulns
		{
			Name: "folder of supported sbom with vulns",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/"},
			Exit: 1,
		},
		// one specific supported sbom with vulns
		{
			Name: "one specific supported sbom with vulns",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		// one specific supported sbom with vulns and invalid PURLs
		{
			Name: "one specific supported sbom with invalid PURLs",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/bad-purls.cdx.xml"},
			Exit: 0,
		},
		// one specific supported sbom with duplicate PURLs
		{
			Name: "one specific supported sbom with duplicate PURLs",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/with-duplicates.cdx.xml"},
			Exit: 1,
		},
		// one file that does not match the supported sbom file names
		{
			Name: "one file that does not match the supported sbom file names",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/locks-many/composer.lock"},
			Exit: 127,
		},
		// one specific unsupported lockfile
		{
			Name: "one specific unsupported lockfile",
			Args: []string{"", "source", "./fixtures/locks-many/not-a-lockfile.toml"},
			Exit: 128,
		},
		// all supported lockfiles in the directory should be checked
		{
			Name: "Scan locks-many",
			Args: []string{"", "source", "./fixtures/locks-many"},
			Exit: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			Name: "all supported lockfiles in the directory should be checked",
			Args: []string{"", "source", "./fixtures/locks-many-with-invalid"},
			Exit: 127,
		},
		// no lockfiles present in a directory
		{
			Name: "no_lockfiles_without_recursion_or_allow_flag_give_an_error",
			Args: []string{"", "source", "./fixtures/locks-none"},
			Exit: 128,
		},
		{
			Name: "no_lockfiles_without_recursion_but_with_allow_flag_are_fine",
			Args: []string{"", "source", "--allow-no-lockfiles", "./fixtures/locks-none"},
			Exit: 0,
		},
		{
			Name: "no_lockfiles_with_allow_flag_but_another_error_happens_is_not_fine",
			Args: []string{"", "source", "--allow-no-lockfiles", "./fixtures/locks-none-does-not-exist"},
			Exit: 127,
		},
		{
			Name: "no_lockfiles_with_recursion_but_without_allow_flag_are_fine",
			Args: []string{"", "source", "--recursive", "./fixtures/locks-none"},
			Exit: 0,
		},
		{
			Name: "no_lockfiles_with_recursion_and_with_allow_flag_are_fine",
			Args: []string{"", "source", "--recursive", "--allow-no-lockfiles", "./fixtures/locks-none"},
			Exit: 0,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			Name: "only the files in the given directories are checked by default (no recursion)",
			Args: []string{"", "source", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		// nested directories are checked when `--recursive` is passed
		{
			Name: "nested directories are checked when `--recursive` is passed",
			Args: []string{"", "source", "--recursive", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		// .gitignored files
		{
			Name: ".gitignored files",
			Args: []string{"", "source", "--recursive", "./fixtures/locks-gitignore"},
			Exit: 0,
		},
		// ignoring .gitignore
		{
			Name: "ignoring .gitignore",
			Args: []string{"", "source", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			Exit: 0,
		},
		{
			Name: "json output",
			Args: []string{"", "source", "--format", "json", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// output format: sarif
		{
			Name: "Empty sarif output",
			Args: []string{"", "source", "--format", "sarif", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "Sarif with vulns",
			Args: []string{"", "source", "--format", "sarif", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		// output format: gh-annotations
		{
			Name: "Empty gh-annotations output",
			Args: []string{"", "source", "--format", "gh-annotations", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "gh-annotations with vulns",
			Args: []string{"", "source", "--format", "gh-annotations", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		// output format: markdown table
		{
			Name: "output format: markdown table",
			Args: []string{"", "source", "--format", "markdown", "--config", "./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		// output format: cyclonedx 1.4
		{
			Name: "Empty cyclonedx 1.4 output",
			Args: []string{"", "source", "--format", "cyclonedx-1-4", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "cyclonedx 1.4 output",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "cyclonedx-1-4", "--all-packages", "./fixtures/locks-insecure"},
			Exit: 1,
		},
		// output format: cyclonedx 1.5
		{
			Name: "Empty cyclonedx 1.5 output",
			Args: []string{"", "source", "--format", "cyclonedx-1-5", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "cyclonedx 1.5 output",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "cyclonedx-1-5", "--all-packages", "./fixtures/locks-insecure"},
			Exit: 1,
		},
		// output format: unsupported
		{
			Name: "output format: unsupported",
			Args: []string{"", "source", "--format", "unknown", "./fixtures/locks-many/composer.lock"},
			Exit: 127,
		},
		// one specific supported lockfile with ignore
		{
			Name: "one specific supported lockfile with ignore",
			Args: []string{"", "source", "./fixtures/locks-test-ignore/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "invalid --verbosity value",
			Args: []string{"", "source", "--verbosity", "unknown", "./fixtures/locks-many/composer.lock"},
			Exit: 127,
		},
		{
			Name: "verbosity level = error",
			Args: []string{"", "source", "--verbosity", "error", "--format", "table", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "verbosity level = info",
			Args: []string{"", "source", "--verbosity", "info", "--format", "table", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "PURL SBOM case sensitivity (api)",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--format", "table", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "PURL SBOM case sensitivity (local)",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "--download-offline-databases", "--format", "table", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		// Go project with an overridden go version
		{
			Name: "Go project with an overridden go version",
			Args: []string{"", "source", "--config=./fixtures/go-project/go-version-config.toml", "./fixtures/go-project"},
			Exit: 0,
		},
		// Go project with an overridden go version, recursive
		{
			Name: "Go project with an overridden go version, recursive",
			Args: []string{"", "source", "--config=./fixtures/go-project/go-version-config.toml", "-r", "./fixtures/go-project"},
			Exit: 0,
		},
		// broad config file that overrides a whole ecosystem
		{
			Name: "config file can be broad",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-composite-config.toml", "--licenses=MIT", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json", "./fixtures/locks-many", "./fixtures/locks-insecure", "./fixtures/maven-transitive"},
			Exit: 1,
		},
		// ignored vulnerabilities and packages without a reason should be called out
		{
			Name: "ignores without reason should be explicitly called out",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-reasonless-ignores-config.toml", "./fixtures/locks-many/package-lock.json", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// invalid config file
		{
			Name: "config file is invalid",
			Args: []string{"", "source", "./fixtures/config-invalid"},
			Exit: 130,
		},
		// config file with unknown keys
		{
			Name: "config files cannot have unknown keys",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-unknown-config.toml", "./fixtures/locks-many"},
			Exit: 127,
		},
		// config file with multiple ignores with the same id
		{
			Name: "config files should not have multiple ignores with the same id",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-duplicate-config.toml", "./fixtures/locks-many"},
			Exit: 0,
		},
		// a bunch of requirements.txt files with different names
		{
			Name: "requirements.txt can have all kinds of names",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-requirements"},
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

func TestCommand_ExplicitExtractors(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "empty_extractors_flag_does_nothing",
			Args: []string{"", "source", "--experimental-extractors="},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_specified_individually",
			Args: []string{
				"", "source",
				"--experimental-extractors=sbom/spdx",
				"--experimental-extractors=sbom/cdx",
				"--experimental-disable-extractors=sbom",
			},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_specified_together",
			Args: []string{
				"", "source",
				"--experimental-extractors=sbom/spdx,sbom/cdx",
				"--experimental-disable-extractors=sbom",
			},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_with_presets",
			Args: []string{
				"", "source",
				"--experimental-extractors=sbom",
				"--experimental-disable-extractors=sbom",
			},
			Exit: 127,
		},
		{
			// this will scan just the package-lock.json file as we've not enabled
			// extractors for any of the other lockfiles
			Name: "scanning_directory_with_one_specific_extractor_enabled",
			Args: []string{
				"", "source",
				"--experimental-extractors=javascript/packagelockjson",
				"./fixtures/locks-many",
			},
			Exit: 0,
		},
		{
			Name: "scanning_directory_with_an_extractor_that_does_not_exist",
			Args: []string{
				"", "source",
				"--experimental-extractors=javascript/packagelockjson",
				"--experimental-extractors=custom/extractor",
				"--experimental-disable-extractors=custom/anotherextractor",
				"./fixtures/locks-many",
			},
			Exit: 127,
		},
		{
			// this will scan just the package-lock.json and composer.lock files as
			// we've not enabled extractors for any of the other lockfiles
			Name: "scanning_directory_with_a_couple_of_specific_extractors_enabled_individually",
			Args: []string{
				"", "source",
				"--experimental-extractors=javascript/packagelockjson",
				"--experimental-extractors=php/composerlock",
				"./fixtures/locks-many",
			},
			Exit: 0,
		},
		{
			// this will scan just the package-lock.json and composer.lock files as
			// we've not enabled extractors for any of the other lockfiles
			Name: "scanning_directory_with_a_couple_of_specific_extractors_enabled_specified_together",
			Args: []string{
				"", "source",
				"--experimental-extractors=javascript/packagelockjson,php/composerlock",
				"./fixtures/locks-many",
			},
			Exit: 0,
		},
		{
			// this should result in all files within the directory being scanned
			// except for the package-lock.json
			Name: "scanning_directory_with_one_specific_extractor_disabled",
			Args: []string{
				"", "source",
				"--experimental-disable-extractors=javascript/packagelockjson",
				"./fixtures/locks-many",
			},
			Exit: 0,
		},
		{
			// this will scan just the package lock, since we're requested that file
			// specifically and have enabled just that extractor
			Name: "scanning_file_with_one_specific_extractor_enabled",
			Args: []string{
				"", "source",
				"--experimental-extractors=javascript/packagelockjson",
				"./fixtures/locks-many/package-lock.json",
			},
			Exit: 0,
		},
		{
			// this will result in an error about not being able to find any package sources
			// since we've requested a composer.lock be scanned without the extractor enabled
			Name: "scanning_file_with_one_different_extractor_enabled",
			Args: []string{
				"", "source",
				"--experimental-extractors=javascript/packagelockjson",
				"./fixtures/locks-many/composer.lock",
			},
			Exit: 128,
		},
		{
			// this will result in an error about not being able to determine the extractor
			// since we've requested the file to be parsed with a specific extractor
			// that we've also disabled
			Name: "scanning_file_with_parse_as_but_specific_extractor_disabled",
			Args: []string{
				"", "source",
				"--experimental-disable-extractors=javascript/packagelockjson",
				"-L", "package-lock.json:./fixtures/locks-many/composer.lock",
			},
			Exit: 127,
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
			Args: []string{"", "source",
				"--call-analysis=go",
				"--config=./fixtures/osv-scanner-call-analysis-config.toml",
				"./fixtures/call-analysis-go-project"},
			Exit: 1,
		},
		{
			Name: "Run with govulncheck all uncalled",
			Args: []string{"", "source",
				"--call-analysis=go",
				"--config=./fixtures/osv-scanner-call-analysis-config.toml",
				"./fixtures/call-analysis-go-project-all-uncalled"},
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

func TestCommand_LockfileWithExplicitParseAs(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "unsupported parse-as",
			Args: []string{"", "source", "-L", "my-file:./fixtures/locks-many/composer.lock"},
			Exit: 127,
		},
		{
			Name: "empty is default",
			Args: []string{
				"",
				"source",
				"-L",
				":" + filepath.FromSlash("./fixtures/locks-many/composer.lock"),
			},
			Exit: 0,
		},
		{
			Name: "empty works as an escape (no fixture because it's not valid on Windows)",
			Args: []string{
				"",
				"source",
				"-L",
				":" + filepath.FromSlash("./path/to/my:file"),
			},
			Exit: 127,
		},
		{
			Name: "empty works as an escape (no fixture because it's not valid on Windows)",
			Args: []string{
				"",
				"source",
				"-L",
				":" + filepath.FromSlash("./path/to/my:project/package-lock.json"),
			},
			Exit: 127,
		},
		{
			Name: "one lockfile with local path",
			Args: []string{"", "source", "--lockfile=go.mod:./fixtures/locks-many/replace-local.mod"},
			Exit: 0,
		},
		{
			Name: "when an explicit parse-as is given, it's applied to that file",
			Args: []string{
				"",
				"source",
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
				"source",
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
				"source",
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
				"source",
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
				"source",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-many/yarn.lock"),
			},
			Exit: 127,
		},
		{
			Name: "\"apk-installed\" is supported",
			Args: []string{
				"",
				"source",
				"-L",
				"apk-installed:" + filepath.FromSlash("./fixtures/locks-many/installed"),
			},
			Exit: 0,
		},
		{
			Name: "\"dpkg-status\" is supported",
			Args: []string{
				"",
				"source",
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
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json"},
			Exit: 1,
		},
		{
			Name: "scanning osv-scanner custom format output json",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json", "--format=sarif"},
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
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "one specific supported sbom with vulns",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/postgres-stretch.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "one specific unsupported lockfile",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./fixtures/locks-many/not-a-lockfile.toml"},
			Exit: 128,
		},
		{
			Name: "all supported lockfiles in the directory should be checked",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./fixtures/locks-many"},
			Exit: 0,
		},
		{
			Name: "all supported lockfiles in the directory should be checked",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./fixtures/locks-many-with-invalid"},
			Exit: 127,
		},
		{
			Name: "only the files in the given directories are checked by default (no recursion)",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "nested directories are checked when `--recursive` is passed",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--recursive", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: ".gitignored files",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--recursive", "./fixtures/locks-gitignore"},
			Exit: 0,
		},
		{
			Name: "ignoring .gitignore",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			Exit: 0,
		},
		{
			Name: "output with json",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--format", "json", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "output format: markdown table",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--format", "markdown", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "database should be downloaded only when offline is set",
			Args: []string{"", "source", "--download-offline-databases", "./fixtures/locks-many"},
			Exit: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			if testutility.IsAcceptanceTesting() {
				testDir := testutility.CreateTestDir(t)
				old := tt.Args
				tt.Args = []string{"", "source", "--local-db-path", testDir}
				tt.Args = append(tt.Args, old[2:]...)
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
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "./fixtures/locks-requirements", "./fixtures/locks-many"},
			Exit: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			testDir := testutility.CreateTestDir(t)
			old := tt.Args
			tt.Args = []string{"", "source", "--local-db-path", testDir}
			tt.Args = append(tt.Args, old[2:]...)

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
			Args: []string{"", "source", "--licenses", "./fixtures/locks-many"},
			Exit: 0,
		},
		{
			Name: "No vulnerabilities with license summary in markdown",
			Args: []string{"", "source", "--licenses", "--format=markdown", "./fixtures/locks-many"},
			Exit: 0,
		},
		{
			Name: "Vulnerabilities and license summary",
			Args: []string{"", "source", "--licenses", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Vulnerabilities and license violations with allowlist",
			Args: []string{"", "source", "--licenses=MIT", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Vulnerabilities and all license violations allowlisted",
			Args: []string{"", "source", "--licenses=Apache-2.0", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Some packages with license violations and show-all-packages in json",
			Args: []string{"", "source", "--format=json", "--licenses=MIT", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Some packages with ignored licenses",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-complex-licenses-config.toml", "--licenses=MIT", "./fixtures/locks-many", "./fixtures/locks-insecure"},
			Exit: 1,
		},
		{
			Name: "Some packages with license violations in json",
			Args: []string{"", "source", "--format=json", "--licenses=MIT", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "No license violations and show-all-packages in json",
			Args: []string{"", "source", "--format=json", "--licenses=MIT,Apache-2.0", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Show all Packages with license summary in json",
			Args: []string{"", "source", "--format=json", "--licenses", "--all-packages", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Licenses in summary mode json",
			Args: []string{"", "source", "--format=json", "--licenses", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Licenses with expressions",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-expressive-licenses-config.toml", "--licenses=MIT,BSD-3-Clause", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Licenses with invalid licenses in flag",
			Args: []string{"", "source", "--licenses=MIT,something-something", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 127,
		},
		{
			Name: "Licenses with invalid expression in config",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-invalid-licenses-config.toml", "--licenses=MIT,BSD-3-Clause", "./fixtures/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "When offline licenses summary cannot be printed",
			Args: []string{"", "source", "--offline", "--licenses", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 127,
		},
		{
			Name: "When offline licenses cannot be checked",
			Args: []string{"", "source", "--offline", "--licenses=MIT", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/locks-many/package-lock.json"},
			Exit: 127,
		},
		{
			Name: "When offline licenses are still validated",
			Args: []string{"", "source", "--offline", "--licenses=MIT,something-something", "./fixtures/locks-many/package-lock.json"},
			Exit: 127,
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
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/maven-transitive/pom.xml"},
			Exit: 1,
		},
		{
			Name: "scans transitive dependencies by specifying pom.xml",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/abc.xml"},
			Exit: 1,
		},
		{
			Name: "scans pom.xml with non UTF-8 encoding",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/encoding.xml"},
			Exit: 1,
		},
		{
			// Direct dependencies do not have any vulnerability.
			Name: "does not scan transitive dependencies for pom.xml with offline mode",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--offline", "--download-offline-databases", "./fixtures/maven-transitive/pom.xml"},
			Exit: 0,
		},
		{
			// Direct dependencies do not have any vulnerability.
			Name: "does not scan transitive dependencies for pom.xml with no-resolve",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--no-resolve", "./fixtures/maven-transitive/pom.xml"},
			Exit: 0,
		},
		{
			Name: "scans dependencies from multiple registries",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "-L", "pom.xml:./fixtures/maven-transitive/registry.xml"},
			Exit: 1,
		},
		{
			Name: "resolve transitive dependencies with native data source",
			Args: []string{"", "source", "--config=./fixtures/osv-scanner-empty-config.toml", "--data-source=native", "-L", "pom.xml:./fixtures/maven-transitive/registry.xml"},
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
			Args: []string{"", "source", "-L", "./fixtures/locks-scalibr/uv.lock"},
			Exit: 1,
		},
		{
			Name: "depsjson",
			Args: []string{"", "source", "-L", "deps.json:./fixtures/locks-scalibr/depsjson"},
			Exit: 1,
		},
		{
			Name: "cabal.project.freeze",
			Args: []string{"", "source", "-L", "./fixtures/locks-scalibr/cabal.project.freeze"},
			Exit: 1,
		},
		{
			Name: "stack.yaml.lock",
			Args: []string{"", "source", "-L", "./fixtures/locks-scalibr/stack.yaml.lock"},
			Exit: 0,
		},
		{
			Name: "packages.config",
			Args: []string{"", "source", "-L", "./fixtures/locks-scalibr/packages.config"},
			Exit: 0,
		},
		{
			Name: "packages.lock.json",
			Args: []string{"", "source", "-L", "./fixtures/locks-scalibr/packages.lock.json"},
			Exit: 0,
		},
		/*
			{
				name: "Package.resolved",
				args: []string{"", "source", "-L", "./fixtures/locks-scalibr/Package.resolved"},
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

func TestCommandNonGit(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)
	err := os.CopyFS(testDir, os.DirFS("./fixtures/locks-many"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []testcmd.Case{
		// one specific supported lockfile
		{
			Name: "one specific supported lockfile",
			Args: []string{"", "source", filepath.Join(testDir, "composer.lock")},
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
