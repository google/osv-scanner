package source_test

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestCommand(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		// one specific supported lockfile
		{
			Name: "one_specific_supported_lockfile",
			Args: []string{"", "source", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		// one specific supported lockfile, explicitly not offline
		{
			Name: "one_specific_supported_lockfile_with_offline_explicitly_false",
			Args: []string{"", "source", "--offline=false", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		// one specific supported sbom with vulns
		{
			Name: "folder_of_supported_sbom_with_vulns",
			Args: []string{"", "source", "./testdata/sbom-insecure/"},
			Exit: 1,
		},
		// one specific supported sbom with only unimportant
		{
			Name: "folder_of_supported_sbom_with_only_unimportant",
			Args: []string{"", "source", "./testdata/sbom-insecure/only-unimportant.spdx.json"},
			Exit: 0,
		},
		// one specific supported sbom with only unimportant but with --all-vulns
		{
			Name: "folder_of_supported_sbom_with_only_unimportant",
			Args: []string{"", "source", "--all-vulns", "./testdata/sbom-insecure/only-unimportant.spdx.json"},
			Exit: 1,
		},
		// one specific supported sbom with vulns
		{
			Name: "one_specific_supported_sbom_with_vulns",
			Args: []string{"", "source", "--sbom", "./testdata/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "one_specific_supported_sbom_with_vulns_using_-L_flag",
			Args: []string{"", "source", "-L", "./testdata/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		// one specific supported sbom with vulns and invalid PURLs
		{
			Name: "one_specific_supported_sbom_with_invalid_PURLs",
			Args: []string{"", "source", "--sbom", "./testdata/sbom-insecure/bad-purls.cdx.xml"},
			Exit: 0,
		},
		{
			Name: "one_specific_supported_sbom_with_invalid_PURLs_using_-L_flag",
			Args: []string{"", "source", "-L", "./testdata/sbom-insecure/bad-purls.cdx.xml"},
			Exit: 0,
		},
		// one specific supported sbom with duplicate PURLs
		{
			Name: "one_specific_supported_sbom_with_duplicate_PURLs",
			Args: []string{"", "source", "--sbom", "./testdata/sbom-insecure/with-duplicates.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "one_specific_supported_sbom_with_duplicate_PURLs_using_-L_flag",
			Args: []string{"", "source", "-L", "./testdata/sbom-insecure/with-duplicates.cdx.xml"},
			Exit: 1,
		},
		// one file that does not match the supported sbom file names
		{
			Name: "one_file_that_does_not_match_the_supported_sbom_file_names",
			Args: []string{"", "source", "--sbom", "./testdata/locks-many/composer.lock"},
			Exit: 127,
		},
		{
			Name: "one_file_that_does_not_match_the_supported_sbom_file_names_using_-L_flag",
			Args: []string{"", "source", "-L", "spdx:./testdata/locks-many/composer.lock"},
			Exit: 127,
		},
		// one specific unsupported lockfile
		{
			Name: "one_specific_unsupported_lockfile",
			Args: []string{"", "source", "./testdata/locks-many/not-a-lockfile.toml"},
			Exit: 128,
		},
		// all supported lockfiles in the directory should be checked
		{
			Name: "Scan_locks-many",
			Args: []string{"", "source", "./testdata/locks-many"},
			Exit: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			Name: "all_supported_lockfiles_in_the_directory_should_be_checked",
			Args: []string{"", "source", "./testdata/locks-many-with-invalid"},
			Exit: 127,
		},
		// no lockfiles present in a directory
		{
			Name: "no_lockfiles_without_recursion_or_allow_flag_give_an_error",
			Args: []string{"", "source", "./testdata/locks-none"},
			Exit: 128,
		},
		{
			Name: "no_lockfiles_without_recursion_but_with_allow_flag_are_fine",
			Args: []string{"", "source", "--allow-no-lockfiles", "./testdata/locks-none"},
			Exit: 0,
		},
		{
			Name: "no_lockfiles_with_allow_flag_but_another_error_happens_is_not_fine",
			Args: []string{"", "source", "--allow-no-lockfiles", "./testdata/locks-none-does-not-exist"},
			Exit: 127,
		},
		{
			Name: "no_lockfiles_with_recursion_but_without_allow_flag_are_fine",
			Args: []string{"", "source", "--recursive", "./testdata/locks-none"},
			Exit: 0,
		},
		{
			Name: "no_lockfiles_with_recursion_and_with_allow_flag_are_fine",
			Args: []string{"", "source", "--recursive", "--allow-no-lockfiles", "./testdata/locks-none"},
			Exit: 0,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			Name: "only_the_files_in_the_given_directories_are_checked_by_default_(no_recursion)",
			Args: []string{"", "source", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		// nested directories are checked when `--recursive` is passed
		{
			Name: "nested_directories_are_checked_when_`--recursive`_is_passed",
			Args: []string{"", "source", "--recursive", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		// .gitignored files
		{
			Name: ".gitignored_files",
			Args: []string{"", "source", "--recursive", "./testdata/locks-gitignore"},
			Exit: 0,
		},
		// ignoring .gitignore
		{
			Name: "ignoring_.gitignore",
			Args: []string{"", "source", "--recursive", "--no-ignore", "./testdata/locks-gitignore"},
			Exit: 0,
		},
		// experimental exclude flag tests
		{
			Name: "exclude_with_exact_directory_name",
			Args: []string{"", "source", "--recursive", "--experimental-exclude=nested", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "exclude_with_glob_pattern",
			Args: []string{"", "source", "--recursive", "--experimental-exclude=g:**/nested/**", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "exclude_with_regex_pattern",
			Args: []string{"", "source", "--recursive", "--experimental-exclude=r:/nested$", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "exclude_with_invalid_regex_returns_error",
			Args: []string{"", "source", "--experimental-exclude=r:[invalid", "./testdata/locks-many"},
			Exit: 127,
		},
		{
			Name: "exclude_with_multiple_exact_directories",
			Args: []string{"", "source", "--recursive", "--experimental-exclude=nested", "--experimental-exclude=other", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "exclude_with_multiple_pattern_types",
			Args: []string{"", "source", "--recursive", "--experimental-exclude=nested", "--experimental-exclude=g:**/vendor/**", "--experimental-exclude=r:\\.cache$", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "json_output",
			Args: []string{"", "source", "--format", "json", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		// output format: sarif
		{
			Name: "Empty_sarif_output",
			Args: []string{"", "source", "--format", "sarif", "./testdata/locks-many/composer.lock"},
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.ReplacePartialFingerprintHash,
			},
			Exit: 0,
		},
		{
			Name: "Sarif_with_vulns",
			Args: []string{"", "source", "--format", "sarif", "./testdata/locks-many-with-insecure/package-lock.json"},
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.ReplacePartialFingerprintHash,
			},
			Exit: 1,
		},
		// output format: gh-annotations
		{
			Name: "Empty_gh-annotations_output",
			Args: []string{"", "source", "--format", "gh-annotations", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "gh-annotations_with_vulns",
			Args: []string{"", "source", "--format", "gh-annotations", "./testdata/locks-many-with-insecure/package-lock.json"},
			Exit: 1,
		},
		// output format: markdown table
		{
			Name: "output_format:_markdown_table",
			Args: []string{"", "source", "--format", "markdown", "./testdata/locks-many-with-insecure/package-lock.json"},
			Exit: 1,
		},
		// output format: cyclonedx 1.4
		{
			Name: "Empty_cyclonedx_1.4_output",
			Args: []string{"", "source", "--format", "cyclonedx-1-4", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "cyclonedx_1.4_output",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-empty-config.toml", "--format", "cyclonedx-1-4", "--all-packages", "./testdata/locks-insecure"},
			Exit: 1,
		},
		// output format: cyclonedx 1.5
		{
			Name: "Empty_cyclonedx_1.5_output",
			Args: []string{"", "source", "--format", "cyclonedx-1-5", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "cyclonedx_1.5_output",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-empty-config.toml", "--format", "cyclonedx-1-5", "--all-packages", "./testdata/locks-insecure"},
			Exit: 1,
		},
		// output format: spdx 2.3
		{
			Name: "Empty_spdx_2.3_output",
			Args: []string{"", "source", "--format", "spdx-2-3", "./testdata/locks-many/composer.lock"},
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.NormalizeCreateDateSPDX,
			},
			Exit: 0,
		},
		{
			Name: "spdx_2.3_output", // SPDX does not support outputting vulnerabilties
			Args: []string{"", "source", "--config=./testdata/osv-scanner-empty-config.toml", "--format", "spdx-2-3", "--all-packages", "./testdata/locks-insecure"},
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.NormalizeCreateDateSPDX,
			},
			Exit: 1,
		},
		// output format: unsupported
		{
			Name: "output_format:_unsupported",
			Args: []string{"", "source", "--format", "unknown", "./testdata/locks-many/composer.lock"},
			Exit: 127,
		},
		// one specific supported lockfile with ignore
		{
			Name: "one_specific_supported_lockfile_with_ignore",
			Args: []string{"", "source", "./testdata/locks-test-ignore/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "invalid_--verbosity_value",
			Args: []string{"", "source", "--verbosity", "unknown", "./testdata/locks-many/composer.lock"},
			Exit: 127,
		},
		{
			Name: "verbosity_level_=_error",
			Args: []string{"", "source", "--verbosity", "error", "--format", "table", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "verbosity_level_=_info",
			Args: []string{"", "source", "--verbosity", "info", "--format", "table", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "PURL_SBOM_case_sensitivity_(api)",
			Args: []string{"", "source", "--format", "table", "./testdata/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "PURL_SBOM_case_sensitivity_(local)",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--format", "table", "./testdata/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		// Go project with an overridden go version and licenses
		{
			Name: "Go_project_with_an_overridden_go_version_and_licences",
			Args: []string{"", "source", "--config=./testdata/go-project/go-version-config.toml", "--licenses", "./testdata/go-project"},
			Exit: 0,
		},
		// Go project with an overridden go version
		{
			Name: "Go_project_with_an_overridden_go_version",
			Args: []string{"", "source", "--config=./testdata/go-project/go-version-config.toml", "./testdata/go-project"},
			Exit: 0,
		},
		// Go project with an overridden go version, recursive
		{
			Name: "Go_project_with_an_overridden_go_version,_recursive",
			Args: []string{"", "source", "--config=./testdata/go-project/go-version-config.toml", "-r", "./testdata/go-project"},
			Exit: 0,
		},
		// broad config file that overrides a whole ecosystem
		{
			Name: "config_file_can_be_broad",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-composite-config.toml", "--licenses=MIT", "-L", "osv-scanner:./testdata/locks-insecure/osv-scanner-flutter-deps.json", "./testdata/locks-many-with-insecure", "./testdata/locks-insecure", "./testdata/maven-transitive"},
			Exit: 1,
		},
		// ignored vulnerabilities and packages without a reason should be called out
		{
			Name: "ignores_without_reason_should_be_explicitly_called_out",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-reasonless-ignores-config.toml", "./testdata/locks-many-with-insecure/package-lock.json", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		// invalid config file
		{
			Name: "config_file_is_invalid",
			Args: []string{"", "source", "./testdata/config-invalid"},
			Exit: 130,
		},
		// config file with unknown keys
		{
			Name: "config_files_cannot_have_unknown_keys",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-unknown-config.toml", "./testdata/locks-many"},
			Exit: 127,
		},
		// config file with multiple ignores with the same id
		{
			Name: "config_files_should_not_have_multiple_ignores_with_the_same_id",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-duplicate-config.toml", "./testdata/locks-many"},
			Exit: 0,
		},
		// a bunch of requirements.txt files with different names
		// --no-resolve is used as transitive resolution tests are in a separate section
		{
			Name: "requirements.txt_can_have_all_kinds_of_names",
			Args: []string{"", "source", "./testdata/locks-requirements", "--no-resolve"},
			Exit: 1,
		},
		{
			Name: "go_packages_in_osv-scanner.json_format",
			Args: []string{"", "source", "-L", "osv-scanner:./testdata/locks-insecure/osv-scanner.json"},
			Exit: 1,
		},
		{
			Name: "help",
			Args: []string{"", "source", "--help"},
			Exit: 127,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_Config_UnusedIgnores(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "unused_ignores_are_reported_with_specific_config_and_file",
			Args: []string{"", "source", "--config", "testdata/osv-scanner-partial-ignores-config.toml", "testdata/sbom-insecure/alpine.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "unused_ignores_are_reported_with_specific_config_and_multiple_files",
			Args: []string{"", "source", "--config", "testdata/osv-scanner-partial-ignores-config.toml", "testdata/sbom-insecure/alpine.cdx.xml", "testdata/sbom-insecure/postgres-stretch.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "unused_ignores_are_reported_with_specific_config_and_file",
			Args: []string{"", "source", "--config", "testdata/osv-scanner-partial-ignores-config.toml", "testdata/sbom-insecure"},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_JavareachArchive(t *testing.T) {
	t.Parallel()

	testutility.SkipIfShort(t)

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "jars_can_be_scanned_without_call_analysis",
			Args: []string{"", "source", "--all-vulns", "--experimental-plugins=artifact", "./testdata/artifact/javareach_test.jar"},
			Exit: 1,
		},
		{
			Name: "jars_can_be_scanned_with_call_analysis",
			Args: []string{"", "source", "--call-analysis=jar", "--all-vulns", "--experimental-plugins=artifact", "./testdata/artifact/javareach_test.jar"},
			Exit: 1,
		},
		{
			Name: "jars_can_be_scanned_with_call_analysis_and_disabled_enricher",
			Args: []string{"", "source", "--call-analysis=jar", "--experimental-disable-plugins=reachability/java", "--all-vulns", "--experimental-plugins=artifact", "./testdata/artifact/javareach_test.jar"},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_HomebrewWithAnnotators(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "darwin" {
		testutility.Skip(t, "The detector in this test only works on Darwin")
	}

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "homebrew_extractor_via_artifact_plugin",
			Args: []string{"", "source", "-r", "--no-ignore", "--experimental-plugins=artifact", "./testdata/homebrew/Cellar/"},
			Exit: 1,
		},
		{
			Name: "homebrew_extractor_explicitly_enabled_with_annotator",
			Args: []string{"", "source", "-r", "--no-ignore", "--experimental-plugins=os/homebrew", "--experimental-plugins=misc/brew-source", "./testdata/homebrew/Cellar/"},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_ExplicitExtractors_WithDefaults(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "empty_plugins_flag_does_nothing",
			Args: []string{"", "source", "--experimental-plugins="},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_specified_individually",
			Args: []string{
				"", "source",
				"--experimental-plugins=sbom/spdx",
				"--experimental-plugins=sbom/cdx",
				"--experimental-disable-plugins=sbom",
			},
			Exit: 128,
		},
		{
			Name: "extractors_cancelled_out_specified_together",
			Args: []string{
				"", "source",
				"--experimental-plugins=sbom/spdx,sbom/cdx",
				"--experimental-disable-plugins=sbom",
			},
			Exit: 128,
		},
		{
			Name: "extractors_cancelled_out_with_presets",
			Args: []string{
				"", "source",
				"--experimental-plugins=sbom",
				"--experimental-disable-plugins=sbom",
			},
			Exit: 128,
		},
		{
			// this will scan all the lockfiles as we have not explicitly disabled the
			// default extractors for any of the other lockfiles
			Name: "scanning_directory_with_one_specific_extractor_enabled_and_the_defaults",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"./testdata/locks-many",
			},
			Exit: 0,
		},
		{
			Name: "scanning_directory_with_an_extractor_that_does_not_exist",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"--experimental-plugins=custom/extractor",
				"--experimental-disable-plugins=custom/anotherextractor",
				"./testdata/locks-many",
			},
			Exit: 127,
		},
		{
			// this will scan just the package-lock.json and composer.lock files as
			// we've not enabled extractors for any of the other lockfiles
			Name: "scanning_directory_with_a_couple_of_specific_extractors_enabled_individually",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"--experimental-plugins=php/composerlock",
				"./testdata/locks-many",
			},
			Exit: 0,
		},
		{
			// this will scan just the package-lock.json and composer.lock files as
			// we've not enabled extractors for any of the other lockfiles
			Name: "scanning_directory_with_a_couple_of_specific_extractors_enabled_specified_together",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson,php/composerlock",
				"./testdata/locks-many",
			},
			Exit: 0,
		},
		{
			// this should result in all files within the directory being scanned
			// except for the package-lock.json
			Name: "scanning_directory_with_one_specific_extractor_disabled",
			Args: []string{
				"", "source",
				"--experimental-disable-plugins=javascript/packagelockjson",
				"./testdata/locks-many",
			},
			Exit: 0,
		},
		{
			// this will scan just the package lock, since we're requested that file specifically
			Name: "scanning_file_with_one_specific_extractor_enabled",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"./testdata/locks-many/package-lock.json",
			},
			Exit: 0,
		},
		{
			// this will result in no issues since we have left the default plugins enabled
			Name: "scanning_file_with_one_different_extractor_enabled",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"./testdata/locks-many/composer.lock",
			},
			Exit: 0,
		},
		{
			// this will result in an error about not being able to determine the extractor
			// since we've requested the file to be parsed with a specific extractor
			// that we've also disabled
			Name: "scanning_file_with_parse_as_but_specific_extractor_disabled",
			Args: []string{
				"", "source",
				"--experimental-disable-plugins=javascript/packagelockjson",
				"-L", "package-lock.json:./testdata/locks-many/composer.lock",
			},
			Exit: 127,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_ExplicitExtractors_WithoutDefaults(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "empty_plugins_flag_does_nothing",
			Args: []string{"", "source", "--experimental-no-default-plugins", "--experimental-plugins="},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_specified_individually",
			Args: []string{
				"", "source",
				"--experimental-plugins=sbom/spdx",
				"--experimental-plugins=sbom/cdx",
				"--experimental-disable-plugins=sbom",
				"--experimental-no-default-plugins",
			},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_specified_together",
			Args: []string{
				"", "source",
				"--experimental-plugins=sbom/spdx,sbom/cdx",
				"--experimental-disable-plugins=sbom",
				"--experimental-no-default-plugins",
			},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_with_presets",
			Args: []string{
				"", "source",
				"--experimental-plugins=sbom",
				"--experimental-disable-plugins=sbom",
				"--experimental-no-default-plugins",
			},
			Exit: 127,
		},
		{
			// this will scan just the package-lock.json file as we've explicitly
			// disabled the default extractors for any of the other lockfiles
			Name: "scanning_directory_with_one_specific_extractor_enabled_and_no_defaults",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"--experimental-no-default-plugins",
				"./testdata/locks-many",
			},
			Exit: 0,
		},
		{
			Name: "scanning_directory_with_an_extractor_that_does_not_exist",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"--experimental-plugins=custom/extractor",
				"--experimental-disable-plugins=custom/anotherextractor",
				"--experimental-no-default-plugins",
				"./testdata/locks-many",
			},
			Exit: 127,
		},
		{
			// this will scan just the package-lock.json and composer.lock files as
			// we've not enabled extractors for any of the other lockfiles
			Name: "scanning_directory_with_a_couple_of_specific_extractors_enabled_individually",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"--experimental-plugins=php/composerlock",
				"--experimental-no-default-plugins",
				"./testdata/locks-many",
			},
			Exit: 0,
		},
		{
			// this will scan just the package-lock.json and composer.lock files as
			// we've not enabled extractors for any of the other lockfiles
			Name: "scanning_directory_with_a_couple_of_specific_extractors_enabled_specified_together",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson,php/composerlock",
				"--experimental-no-default-plugins",
				"./testdata/locks-many",
			},
			Exit: 0,
		},
		{
			// this should result in all files within the directory being scanned
			// except for the package-lock.json
			Name: "scanning_directory_with_one_specific_extractor_disabled",
			Args: []string{
				"", "source",
				"--experimental-disable-plugins=javascript/packagelockjson",
				"--experimental-no-default-plugins",
				"./testdata/locks-many",
			},
			Exit: 0,
		},
		{
			// this will scan just the package lock, since we're requested that file
			// specifically and have enabled just that extractor
			Name: "scanning_file_with_one_specific_extractor_enabled",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"--experimental-no-default-plugins",
				"./testdata/locks-many/package-lock.json",
			},
			Exit: 0,
		},
		{
			// this will result in an error about not being able to find any package sources
			// since we've requested a composer.lock be scanned without the extractor enabled
			Name: "scanning_file_with_one_different_extractor_enabled",
			Args: []string{
				"", "source",
				"--experimental-plugins=javascript/packagelockjson",
				"--experimental-no-default-plugins",
				"./testdata/locks-many/composer.lock",
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
				"--experimental-disable-plugins=javascript/packagelockjson",
				"--experimental-no-default-plugins",
				"-L", "package-lock.json:./testdata/locks-many/composer.lock",
			},
			Exit: 127,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_CallAnalysis(t *testing.T) {
	t.Parallel()

	// This does require Go toolchain, but the whole project requires go toolchain,
	// so not an external dependency

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "Run_with_govulncheck",
			Args: []string{"", "source",
				"--call-analysis=go",
				"--config=./testdata/osv-scanner-call-analysis-config.toml",
				"./testdata/call-analysis-go-project"},
			Exit: 1,
		},
		{
			Name: "Run_with_govulncheck_all_uncalled",
			Args: []string{"", "source",
				"--call-analysis=go",
				"--config=./testdata/osv-scanner-call-analysis-config.toml",
				"./testdata/call-analysis-go-project-all-uncalled"},
			Exit: 0,
		},
		{
			Name: "Run_with_govulncheck_all_uncalled_but_enabled_all-vulns_flag",
			Args: []string{"", "source",
				"--call-analysis=go",
				"--all-vulns",
				"--config=./testdata/osv-scanner-call-analysis-config.toml",
				"./testdata/call-analysis-go-project-all-uncalled"},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_CallAnalysisRustWithoutUnsafeFlagFails(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	_, stderr := testcmd.RunAndNormalize(t, testcmd.Case{
		Name: "rust_call_analysis_without_acknowledgement",
		Args: []string{
			"",
			"source",
			"--offline",
			"--call-analysis=rust",
			"--allow-no-lockfiles",
			testDir,
		},
		Exit: 127,
	})

	requiredFlag := "--" + helper.AllowUnsafeRustCallAnalysisFlag
	if !strings.Contains(stderr, requiredFlag) {
		t.Fatalf("expected stderr to contain %q, got:\n%s", requiredFlag, stderr)
	}
}

func TestCommand_CallAnalysisRustWithUnsafeFlagSucceeds(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	testcmd.RunAndNormalize(t, testcmd.Case{
		Name: "rust_call_analysis_with_acknowledgement",
		Args: []string{
			"",
			"source",
			"--offline",
			"--call-analysis=rust",
			"--" + helper.AllowUnsafeRustCallAnalysisFlag,
			"--allow-no-lockfiles",
			testDir,
		},
		Exit: 0,
	})
}

func TestCommand_LockfileWithExplicitParseAs(t *testing.T) {
	t.Parallel()

	cwd := testutility.GetCurrentWorkingDirectory(t)
	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "unsupported_parse-as",
			Args: []string{"", "source", "-L", "my-file:./testdata/locks-many/composer.lock"},
			Exit: 127,
		},
		{
			Name: "empty_is_default",
			Args: []string{
				"",
				"source",
				"-L",
				":" + filepath.FromSlash("./testdata/locks-many/composer.lock"),
			},
			Exit: 0,
		},
		{
			Name: "empty_works_as_an_escape_(no_fixture_because_it's_not_valid_on_Windows)",
			Args: []string{
				"",
				"source",
				"-L",
				":" + filepath.FromSlash("./path/to/my:file"),
			},
			Exit: 127,
		},
		{
			Name: "empty_works_as_an_escape_(no_fixture_because_it's_not_valid_on_Windows)",
			Args: []string{
				"",
				"source",
				"-L",
				":" + filepath.FromSlash("./path/to/my:project/package-lock.json"),
			},
			Exit: 127,
		},
		{
			Name: "one_lockfile_with_local_path",
			Args: []string{"", "source", "--lockfile=go.mod:./testdata/locks-many/replace-local.mod"},
			Exit: 0,
		},
		{
			Name: "when_an_explicit_parse-as_is_given,_it's_applied_to_that_file",
			Args: []string{
				"",
				"source",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./testdata/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./testdata/locks-insecure"),
			},
			Exit: 1,
		},
		{
			Name: "multiple,_+_output_order_is_deterministic",
			Args: []string{
				"",
				"source",
				"-L", "package-lock.json:" + filepath.FromSlash("./testdata/locks-insecure/my-package-lock.json"),
				"-L", "yarn.lock:" + filepath.FromSlash("./testdata/locks-insecure/my-yarn.lock"),
				filepath.FromSlash("./testdata/locks-insecure"),
			},
			Exit: 1,
		},
		{
			Name: "multiple,_+_output_order_is_deterministic_2",
			Args: []string{
				"",
				"source",
				"-L", "yarn.lock:" + filepath.FromSlash("./testdata/locks-insecure/my-yarn.lock"),
				"-L", "package-lock.json:" + filepath.FromSlash("./testdata/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./testdata/locks-insecure"),
			},
			Exit: 1,
		},
		{
			Name: "files_that_error_on_parsing_stop_parsable_files_from_being_checked",
			Args: []string{
				"",
				"source",
				"-L",
				"Cargo.lock:" + filepath.FromSlash("./testdata/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./testdata/locks-insecure"),
				filepath.FromSlash("./testdata/locks-many"),
			},
			Exit: 127,
		},
		{
			Name: "parse-as_takes_priority,_even_if_it's_wrong",
			Args: []string{
				"",
				"source",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./testdata/locks-many/yarn.lock"),
			},
			Exit: 127,
		},
		{
			Name: "\"apk-installed\" is supported",
			Args: []string{
				"",
				"source",
				"-L",
				"apk-installed:" + filepath.FromSlash("./testdata/locks-many/installed"),
			},
			Exit: 0,

			// don't intercept requests for this case as the apk extractor reads the OS version
			// of the environment its being run in, and currently does not support being overridden
			HTTPClient: http.DefaultClient,
		},
		{
			Name: "\"dpkg-status\" is supported",
			Args: []string{
				"",
				"source",
				"-L",
				"dpkg-status:" + filepath.FromSlash("./testdata/locks-many/status"),
			},
			Exit: 0,

			// don't intercept requests for this case as the dpkg extractor reads the OS version
			// of the environment its being run in, and currently does not support being overridden
			HTTPClient: http.DefaultClient,
		},
		{
			// if this isn't true, the test would fail along the lines of
			// "could not determine extractor, requested D"
			Name: "absolute_paths_are_automatically_escaped_on_windows",
			Args: []string{
				"",
				"source",
				"-L",
				filepath.FromSlash(filepath.Join(cwd, "./testdata/locks-many/yarn.lock")),
			},
			Exit: 0,
		},
		{
			Name: "absolute_paths_work_with_explicit_escaping",
			Args: []string{
				"",
				"source",
				"-L",
				":" + filepath.FromSlash(filepath.Join(cwd, "./testdata/locks-many/yarn.lock")),
			},
			Exit: 0,
		},
		{
			Name: "absolute_paths_can_have_explicit_parse_as",
			Args: []string{
				"",
				"source",
				"-L",
				"package-lock.json:" + filepath.FromSlash(filepath.Join(cwd, "./testdata/locks-many/yarn.lock")),
			},
			Exit: 127,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			if tt.HTTPClient == nil {
				tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)
			}

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

// TestCommand_GithubActions tests common actions the github actions reusable workflow will run
func TestCommand_GithubActions(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "scanning_osv-scanner_custom_format",
			Args: []string{"", "source", "-L", "osv-scanner:./testdata/locks-insecure/osv-scanner-flutter-deps.json"},
			Exit: 1,
		},
		{
			Name: "scanning_osv-scanner_custom_format_with_git_tag",
			Args: []string{"", "source", "-L", "osv-scanner:./testdata/locks-insecure/osv-scanner-custom-git-tag.json"},
			Exit: 1,
		},
		{
			Name: "scanning_osv-scanner_custom_format_output_json",
			Args: []string{"", "source", "-L", "osv-scanner:./testdata/locks-insecure/osv-scanner-flutter-deps.json", "--format=sarif"},
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.ReplacePartialFingerprintHash,
			},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_LocalDatabases(t *testing.T) {
	t.Parallel()

	testutility.SkipIfShort(t)

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "one_specific_supported_lockfile",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "one_specific_supported_sbom_with_vulns",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./testdata/sbom-insecure/postgres-stretch.cdx.xml"},
			Exit: 1,
		},
		{
			Name: "one_specific_unsupported_lockfile",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./testdata/locks-many/not-a-lockfile.toml"},
			Exit: 128,
		},
		{
			Name: "all_supported_lockfiles_in_the_directory_should_be_checked",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./testdata/locks-many-with-insecure"},
			Exit: 1,
		},
		{
			Name: "all_supported_lockfiles_in_the_directory_should_be_checked",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./testdata/locks-many-with-invalid"},
			Exit: 127,
		},
		{
			Name: "only_the_files_in_the_given_directories_are_checked_by_default_(no_recursion)",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "nested_directories_are_checked_when_`--recursive`_is_passed",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--recursive", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: ".gitignored_files",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--recursive", "./testdata/locks-gitignore"},
			Exit: 0,
		},
		{
			Name: "ignoring_.gitignore",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--recursive", "--no-ignore", "./testdata/locks-gitignore"},
			Exit: 0,
		},
		{
			Name: "output_with_json",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--format", "json", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "output_format:_markdown_table",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--format", "markdown", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "database_should_be_downloaded_only_when_offline_is_set",
			Args: []string{"", "source", "--download-offline-databases", "./testdata/locks-many"},
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

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			// run each test twice since they should provide the same output,
			// and the second run should be fast as the db is already available
			testcmd.RunAndMatchSnapshots(t, tt)
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_LocalDatabases_AlwaysOffline(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "a_bunch_of_different_lockfiles_and_ecosystem",
			Args: []string{"", "source", "--offline", "./testdata/locks-requirements", "./testdata/locks-many-with-insecure"},
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

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			// run each test twice since they should provide the same output,
			// and the second run should be fast as the db is already available
			testcmd.RunAndMatchSnapshots(t, tt)
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_CommitSupport(t *testing.T) {
	t.Parallel()

	testutility.SkipIfShort(t)

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "online_uses_git_commits",
			Args: []string{"", "source", "--lockfile", "osv-scanner:./testdata/locks-git/osv-scanner.json"},
			Exit: 1,
		},
		{
			Name: "offline_uses_git_tags",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "--lockfile", "osv-scanner:./testdata/locks-git/osv-scanner.json"},
			Exit: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_Licenses(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "No_vulnerabilities_with_license_summary",
			Args: []string{"", "source", "--licenses", "./testdata/locks-many"},
			Exit: 0,
		},
		{
			Name: "No_vulnerabilities_with_license_summary_in_markdown",
			Args: []string{"", "source", "--licenses", "--format=markdown", "./testdata/locks-many"},
			Exit: 0,
		},
		{
			Name: "Vulnerabilities_and_license_summary",
			Args: []string{"", "source", "--licenses", "./testdata/locks-many-with-insecure/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Vulnerabilities_and_license_violations_with_allowlist",
			Args: []string{"", "source", "--licenses=MIT", "./testdata/locks-many-with-insecure/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "No_vulnerabilities_but_license_violations_with_allowlist",
			Args: []string{"", "source", "--licenses=Apache-2.0", "--config=./testdata/osv-scanner-empty-config.toml", "./testdata/locks-many/yarn.lock"},
			Exit: 1,
		},
		{
			Name: "Vulnerabilities_and_all_license_violations_allowlisted",
			Args: []string{"", "source", "--licenses=Apache-2.0", "./testdata/locks-many-with-insecure/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Some_packages_with_license_violations_and_show-all-packages_in_json",
			Args: []string{"", "source", "--format=json", "--licenses=MIT", "--all-packages", "./testdata/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Some_packages_with_ignored_licenses",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-complex-licenses-config.toml", "--licenses=MIT", "./testdata/locks-many", "./testdata/locks-insecure"},
			Exit: 1,
		},
		{
			Name: "Some_packages_with_license_violations_in_json",
			Args: []string{"", "source", "--format=json", "--licenses=MIT", "./testdata/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "No_license_violations_and_show-all-packages_in_json",
			Args: []string{"", "source", "--format=json", "--licenses=MIT,Apache-2.0", "--all-packages", "./testdata/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Show_all_Packages_with_license_summary_in_json",
			Args: []string{"", "source", "--format=json", "--licenses", "--all-packages", "./testdata/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Licenses_in_summary_mode_json",
			Args: []string{"", "source", "--format=json", "--licenses", "./testdata/locks-licenses/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "Licenses_with_expressions",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-expressive-licenses-config.toml", "--licenses=MIT,BSD-3-Clause", "./testdata/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "Licenses_with_invalid_licenses_in_flag",
			Args: []string{"", "source", "--licenses=MIT,something-something", "./testdata/locks-licenses/package-lock.json"},
			Exit: 127,
		},
		{
			Name: "Licenses_with_invalid_expression_in_config",
			Args: []string{"", "source", "--config=./testdata/osv-scanner-invalid-licenses-config.toml", "--licenses=MIT,BSD-3-Clause", "./testdata/locks-licenses/package-lock.json"},
			Exit: 1,
		},
		{
			Name: "When_offline_licenses_summary_cannot_be_printed",
			Args: []string{"", "source", "--offline", "--licenses", "./testdata/locks-many/package-lock.json"},
			Exit: 127,
		},
		{
			Name: "When_offline_licenses_cannot_be_checked",
			Args: []string{"", "source", "--offline", "--licenses=MIT", "./testdata/locks-many/package-lock.json"},
			Exit: 127,
		},
		{
			Name: "When_offline_licenses_are_still_validated",
			Args: []string{"", "source", "--offline", "--licenses=MIT,something-something", "./testdata/locks-many/package-lock.json"},
			Exit: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_Transitive(t *testing.T) {
	t.Parallel()

	testutility.SkipIfShort(t)

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "pom.xml_transitive_default",
			Args: []string{"", "source", "./testdata/maven-transitive/pom.xml"},
			Exit: 1,
		},
		{
			Name: "pom.xml_transitive_explicit_lockfile",
			Args: []string{"", "source", "-L", "pom.xml:./testdata/maven-transitive/abc.xml"},
			Exit: 1,
		},
		{
			Name: "pom.xml_multiple_registries",
			Args: []string{"", "source", "-L", "pom.xml:./testdata/maven-transitive/registry.xml"},
			Exit: 1,
		},
		{
			Name: "pom.xml_transitive_native_source",
			Args: []string{"", "source", "--data-source=native", "-L", "pom.xml:./testdata/maven-transitive/registry.xml"},
			Exit: 1,
		},
		{
			Name: "pom.xml_non_utf8_encoding",
			Args: []string{"", "source", "-L", "pom.xml:./testdata/maven-transitive/encoding.xml"},
			Exit: 1,
		},
		{
			Name: "pom.xml_no_resolve_no_transitive",
			Args: []string{"", "source", "--no-resolve", "./testdata/maven-transitive/pom.xml"},
			// Direct dependencies do not have any vulnerability.
			Exit: 0,
		},
		{
			Name: "pom.xml_offline_no_transitive",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./testdata/maven-transitive/pom.xml"},
			// Direct dependencies do not have any vulnerability.
			Exit: 0,
		},
		{
			Name: "pom.xml_enricher_requires_extractor",
			Args: []string{"", "source", "--experimental-disable-plugins=java/pomxml", "./testdata/maven-transitive/abc.xml"},
			Exit: 128,
		},
		{
			Name: "invalid_data_source_error",
			Args: []string{"", "source", "--data-source=github", "-L", "pom.xml:./testdata/maven-transitive/registry.xml"},
			Exit: 127,
		},
		{
			Name: "requirements.txt_transitive_default",
			Args: []string{"", "source", "-L", "./testdata/locks-requirements/requirements.txt"},
			Exit: 1,
		},
		{
			Name: "requirements.txt_transitive_native_source",
			Args: []string{"", "source", "--data-source=native", "-L", "requirements.txt:./testdata/locks-requirements/requirements.txt"},
			Exit: 1,
		},
		{
			Name: "requirements.txt_no_resolve_no_transitive",
			Args: []string{"", "source", "--no-resolve", "./testdata/locks-requirements/requirements.txt"},
			Exit: 1,
		},
		{
			Name: "requirements.txt_offline_no_transitive",
			Args: []string{"", "source", "--offline", "--download-offline-databases", "./testdata/locks-requirements/requirements.txt"},
			Exit: 1,
		},
		{
			Name: "requirements.txt_enricher_requires_extractor",
			Args: []string{"", "source", "--experimental-disable-plugins=python/requirements", "./testdata/locks-requirements/requirements-transitive.txt"},
			Exit: 128,
		},
		{
			Name: "requirements.txt_resolution_fallback",
			Args: []string{"", "source", "./testdata/locks-requirements/unresolvable-requirements.txt"},
			Exit: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_MoreLockfiles(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "uv.lock",
			Args: []string{"", "source", "-L", "./testdata/locks-scalibr/uv.lock"},
			Exit: 1,
		},
		{
			Name: "depsjson",
			Args: []string{"", "source", "-L", "deps.json:./testdata/locks-scalibr/depsjson"},
			Exit: 1,
		},
		{
			Name: "cabal.project.freeze",
			Args: []string{"", "source", "-L", "./testdata/locks-scalibr/cabal.project.freeze"},
			Exit: 1,
		},
		{
			Name: "stack.yaml.lock",
			Args: []string{"", "source", "-L", "./testdata/locks-scalibr/stack.yaml.lock"},
			Exit: 0,
		},
		{
			Name: "packages.config",
			Args: []string{"", "source", "-L", "./testdata/locks-scalibr/packages.config"},
			Exit: 0,
		},
		{
			Name: "packages.lock.json",
			Args: []string{"", "source", "-L", "./testdata/locks-scalibr/packages.lock.json"},
			Exit: 0,
		},
		{
			Name: "gems.locked",
			Args: []string{"", "source", "-L", "./testdata/locks-scalibr/gems.locked"},
			Exit: 1,
		},
		{
			Name: "Podfile.lock_-_Unsupported_ecosystem,_should_not_be_scanned",
			Args: []string{"", "source", "-L", "./testdata/locks-scalibr/Podfile.lock"},
			Exit: 127,
		},
		{
			Name: "Package.resolved_-_Unsupported_ecosystem,_should_not_be_scanned",
			Args: []string{"", "source", "-L", "./testdata/locks-scalibr/Package.resolved"},
			Exit: 127,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommandNonGit(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)
	err := os.CopyFS(testDir, os.DirFS("./testdata/locks-many"))
	if err != nil {
		t.Fatal(err)
	}

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		// one specific supported lockfile
		{
			Name: "one_specific_supported_lockfile",
			Args: []string{"", "source", filepath.Join(testDir, "composer.lock")},
			Exit: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_HtmlFile(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)
	client := testcmd.InsertCassette(t)

	testcmd.RunAndMatchSnapshots(t, testcmd.Case{
		Name: "one_specific_supported_lockfile",
		Args: []string{"", "source", "--format=html", "--output-file", testDir + "/report.html", "./testdata/locks-many/composer.lock"},
		Exit: 0,

		HTTPClient: testcmd.WithTestNameHeader(t, *client),
	})

	_, err := os.Stat(testDir + "/report.html")

	if err != nil {
		t.Errorf("Unexpected %v", err)
	}
}

func TestCommand_HtmlFile_Deprecated(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)
	client := testcmd.InsertCassette(t)

	testcmd.RunAndMatchSnapshots(t, testcmd.Case{
		Name: "one_specific_supported_lockfile",
		Args: []string{"", "source", "--format=html", "--output", testDir + "/report.html", "./testdata/locks-many/composer.lock"},
		Exit: 0,

		HTTPClient: testcmd.WithTestNameHeader(t, *client),
	})

	_, err := os.Stat(testDir + "/report.html")

	if err != nil {
		t.Errorf("Unexpected %v", err)
	}
}

func TestCommand_WithDetector_OnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		testutility.Skip(t, "The detector in this test only works on Linux")
	}

	testDir := testutility.CreateTestDir(t)
	err := os.CopyFS(testDir, os.DirFS("./testdata/locks-many"))
	if err != nil {
		t.Fatal(err)
	}

	err = os.CopyFS(testDir+"/bin", os.DirFS("./testdata/bin"))
	if err != nil {
		t.Fatal(err)
	}

	client := testcmd.InsertCassette(t)

	tests := []struct {
		Name string
		Args []string
		Exit int
		SSHV string
	}{
		{
			Name: "ssh_version_is_before_first_vuln_version",
			Args: []string{
				"", "source",
				"--experimental-plugins", "php/composerlock",
				"--experimental-plugins", "cve/cve-2023-38408",
				filepath.Join(testDir, "composer.lock"),
			},
			Exit: 0,
			SSHV: "OpenSSH_5.4 Ubuntu-3ubuntu0.13, OpenSSL 3.0.2 15 Mar 2022",
		},
		{
			Name: "ssh_version_is_after_last_vuln_version",
			Args: []string{
				"", "source",
				"--experimental-plugins", "php/composerlock",
				"--experimental-plugins", "cve/cve-2023-38408",
				filepath.Join(testDir, "composer.lock"),
			},
			Exit: 0,
			SSHV: "OpenSSH_9.3p2 Ubuntu-3ubuntu0.13, OpenSSL 3.0.2 15 Mar 2022",
		},
		{
			Name: "ssh_version_errors",
			Args: []string{
				"", "source",
				"--experimental-plugins", "php/composerlock",
				"--experimental-plugins", "cve/cve-2023-38408",
				filepath.Join(testDir, "composer.lock"),
			},
			Exit: 0,
			SSHV: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			// append our bin directory to the start of the PATH variable
			// so that our fake ssh script will be invoked by the detector
			t.Setenv("PATH", (testDir+"/bin/:")+os.Getenv("PATH"))
			t.Setenv("OSV_SCANNER_TEST_SSH_VERSION_OUTPUT", tt.SSHV)

			testcmd.RunAndMatchSnapshots(t, testcmd.Case{
				Name: tt.Name,
				Args: tt.Args,
				Exit: tt.Exit,

				HTTPClient: testcmd.WithTestNameHeader(t, *client),
			})
		})
	}
}

func TestCommand_WithDetector_OffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		testutility.Skip(t, "The detector in this test only works on non-linux")
	}

	testDir := testutility.CreateTestDir(t)
	err := os.CopyFS(testDir, os.DirFS("./testdata/locks-many"))
	if err != nil {
		t.Fatal(err)
	}

	err = os.CopyFS(testDir+"/bin", os.DirFS("./testdata/bin"))
	if err != nil {
		t.Fatal(err)
	}

	client := testcmd.InsertCassette(t)

	tests := []struct {
		Name string
		Args []string
		Exit int
		SSHV string
	}{
		{
			Name: "ssh_version_is_before_first_vuln_version",
			Args: []string{
				"", "source",
				"--experimental-plugins", "php/composerlock",
				"--experimental-plugins", "cve/cve-2023-38408",
				filepath.Join(testDir, "composer.lock"),
			},
			Exit: 0,
			SSHV: "OpenSSH_5.4 Ubuntu-3ubuntu0.13, OpenSSL 3.0.2 15 Mar 2022",
		},
		{
			Name: "ssh_version_is_after_last_vuln_version",
			Args: []string{
				"", "source",
				"--experimental-plugins", "php/composerlock",
				"--experimental-plugins", "cve/cve-2023-38408",
				filepath.Join(testDir, "composer.lock"),
			},
			Exit: 0,
			SSHV: "OpenSSH_9.3p2 Ubuntu-3ubuntu0.13, OpenSSL 3.0.2 15 Mar 2022",
		},
		{
			Name: "ssh_version_errors",
			Args: []string{
				"", "source",
				"--experimental-plugins", "php/composerlock",
				"--experimental-plugins", "cve/cve-2023-38408",
				filepath.Join(testDir, "composer.lock"),
			},
			Exit: 0,
			SSHV: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			// append our bin directory to the start of the PATH variable
			// so that our fake ssh script will be invoked by the detector
			t.Setenv("PATH", (testDir+"/bin/:")+os.Getenv("PATH"))
			t.Setenv("OSV_SCANNER_TEST_SSH_VERSION_OUTPUT", tt.SSHV)

			testcmd.RunAndMatchSnapshots(t, testcmd.Case{
				Name: tt.Name,
				Args: tt.Args,
				Exit: tt.Exit,

				HTTPClient: testcmd.WithTestNameHeader(t, *client),
			})
		})
	}
}

func TestCommand_Filter(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "Show_all_Packages_with_empty_config",
			Args: []string{"", "source", "--format=json", "--all-packages", "--config=./testdata/osv-scanner-empty-config.toml", "--lockfile=osv-scanner:./testdata/locks-insecure/osv-scanner-with-unscannables.json"},
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

func TestCommand_FlagDeprecatedPackages(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "package_deprecated_false_no_vuln_json",
			Args: []string{
				"", "source", "--format=json",
				"--experimental-flag-deprecated-packages",
				"./testdata/exp-plugins-pkgdeprecate/clean/Cargo.lock",
			},
			Exit: 0,
		},
		{
			Name: "package_deprecated_true_no_vuln_json",
			Args: []string{
				"", "source", "--format=json",
				"--experimental-flag-deprecated-packages",
				"./testdata/exp-plugins-pkgdeprecate/deprecated-novuln/Cargo.lock",
			},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
			},
		},
		{
			Name: "package_deprecated_true_with_vuln_json",
			Args: []string{
				"", "source", "--format=json",
				"--experimental-flag-deprecated-packages",
				"./testdata/exp-plugins-pkgdeprecate/deprecated-vuln/Cargo.lock",
			},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
			},
		},
		{
			Name: "package_deprecated_npm_json",
			Args: []string{
				"", "source", "--format=json",
				"--experimental-flag-deprecated-packages",
				"./testdata/exp-plugins-pkgdeprecate/deprecated-npm/package-lock.json",
			},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
			},
		},
		{
			Name: "package_deprecated_true_no_vuln_table",
			Args: []string{
				"", "source", "--format=table",
				"--experimental-flag-deprecated-packages",
				"./testdata/exp-plugins-pkgdeprecate/deprecated-novuln/Cargo.lock",
			},
			Exit: 1,
		},
		{
			Name: "package_deprecated_true_with_vuln_table",
			Args: []string{
				"", "source", "--format=table",
				"--experimental-flag-deprecated-packages",
				"./testdata/exp-plugins-pkgdeprecate/deprecated-vuln/Cargo.lock",
			},
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
