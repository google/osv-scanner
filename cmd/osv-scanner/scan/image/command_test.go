package image_test

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestCommand_ExplicitExtractors_WithDefaults(t *testing.T) {
	t.Parallel()
	testutility.SkipIfNotAcceptanceTesting(t, "Requires docker to build the images")

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "add_extractors",
			Args: []string{
				"", "image",
				"--archive",
				"--x-plugins=sbom/spdx",
				"--x-plugins=sbom/cdx",
				"testdata/test-alpine-sbom.tar",
			},
			Exit: 1,
		},
		{
			Name: "extractors_cancelled_out",
			Args: []string{
				"", "image",
				"--archive",
				"--x-plugins=sbom/spdx",
				"--x-plugins=sbom/cdx",
				"--x-disable-plugins=sbom",
				"testdata/test-alpine-sbom.tar",
			},
			Exit: 1,
		},
		{
			Name: "extractors_cancelled_out_with_presets",
			Args: []string{
				"", "image",
				"--archive",
				"--x-plugins=sbom",
				"--x-disable-plugins=sbom",
				"testdata/test-alpine-sbom.tar",
			},
			Exit: 1,
		},
		{
			Name: "extractors_cancelled_out",
			Args: []string{
				"", "image",
				"--archive",
				"--x-plugins=sbom/spdx,sbom/cdx",
				"--x-disable-plugins=sbom",
				"testdata/test-alpine-sbom.tar",
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

func TestCommand_ExplicitExtractors_WithoutDefaults(t *testing.T) {
	t.Parallel()

	testutility.SkipIfNotAcceptanceTesting(t, "Requires docker to build the images")

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "add_extractors",
			Args: []string{
				"", "image",
				"--archive",
				"--x-plugins=sbom/spdx",
				"--x-plugins=sbom/cdx",
				"--x-no-default-plugins",
				"testdata/test-alpine-sbom.tar",
			},
			Exit: 1,
		},
		{
			Name: "extractors_cancelled_out",
			Args: []string{
				"", "image",
				"--archive",
				"--x-plugins=sbom/spdx",
				"--x-plugins=sbom/cdx",
				"--x-disable-plugins=sbom",
				"--x-no-default-plugins",
				"testdata/test-alpine-sbom.tar",
			},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_with_presets",
			Args: []string{
				"", "image",
				"--archive",
				"--x-plugins=sbom",
				"--x-disable-plugins=sbom",
				"--x-no-default-plugins",
				"testdata/test-alpine-sbom.tar",
			},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out",
			Args: []string{
				"", "image",
				"--archive",
				"--x-plugins=sbom/spdx,sbom/cdx",
				"--x-disable-plugins=sbom",
				"--x-no-default-plugins",
				"testdata/test-alpine-sbom.tar",
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

func TestCommand_Docker(t *testing.T) {
	t.Parallel()

	testutility.SkipIfNotAcceptanceTesting(t, "Requires docker (also takes a long time to pull images)")
	testutility.SkipIfShort(t)

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "no_image_argument",
			Args: []string{"", "image"},
			Exit: 127,
		},
		{
			Name: "Fake_alpine_image",
			Args: []string{"", "image", "alpine:non-existent-tag"},
			Exit: 127,
		},
		{
			Name: "Fake_image_entirely",
			Args: []string{"", "image", "this-image-definitely-does-not-exist-abcde:with-tag"},
			Exit: 127,
		},
		{
			Name: "Real_empty_image_with_no_tag,_invalid_scan_target",
			Args: []string{"", "image", "hello-world"},
			Exit: 127, // Invalid scan target
		},
		{
			Name: "Real_empty_image_with_tag",
			Args: []string{"", "image", "hello-world:linux"},
			Exit: 128, // No package found
		},
		{
			Name: "real_empty_image_with_tag_and_allow_no_lockfiles_flag",
			Args: []string{"", "image", "--allow-no-lockfiles", "hello-world:linux"},
			Exit: 0,
		},
		{
			Name: "Real_Alpine_image",
			Args: []string{"", "image", "alpine:3.18.9"},
			Exit: 1,
		},
		{
			// this will result in an error about not being able to find any package sources
			// since we've requested the os/apk extractor disabled, and there's nothing else
			// in the image that we support extracting
			Name: "real_alpine_image_without_apk_extractor_enabled",
			Args: []string{"", "image", "--x-disable-plugins=os/apk", "alpine:3.18.9"},
			Exit: 128,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// Only test on linux, and mac/windows CI/CD does not come with docker preinstalled
			if runtime.GOOS != "linux" {
				testutility.Skip(t, "Skipping Docker-based test as only Linux has Docker installed in CI")
			}

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_OCIImage(t *testing.T) {
	t.Parallel()
	testutility.SkipIfNotAcceptanceTesting(t, "Requires docker to build the images")

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "Invalid_path",
			Args: []string{"", "image", "--archive", "../../testdata/locks-manyoci-image/no-file-here.tar"},
			Exit: 127,
		},
		{
			Name: "Alpine_3.10_image_tar_with_3.18_version_file",
			Args: []string{"", "image", "--archive", "./testdata/test-alpine.tar"},
			Exit: 1,
		},
		{
			Name: "Empty_Ubuntu_22.04_image_tar",
			Args: []string{"", "image", "--archive", "./testdata/test-ubuntu.tar"},
			Exit: 1,
		},
		{
			Name: "Empty_Ubuntu_22.04_image_tar_with_unimportant_vulns",
			Args: []string{"", "image", "--all-vulns", "--archive", "./testdata/test-ubuntu.tar"},
			Exit: 1,
		},
		{
			Name: "Empty_Ubuntu_20.04_image_tar_with_only_unimportant_vulns_shown",
			Args: []string{"", "image", "--archive", "--all-vulns",
				"--config=./testdata/ubuntu20-04-unimportant-config.toml",
				"--all-vulns", "./testdata/test-ubuntu-20-04.tar"},
			Exit: 1,
		},
		{
			// This tests that unimportant vulns are hidden properly
			// If the test is failing (reporting new important vulns), add the package that introduced the vuln as ignore=true to the config.toml
			// The package with unimportant vulns is pcre3, so if a new vulnerability appears for that package, don't ignore the entire package, just ignore the important vulnerability specifically.
			Name: "Empty_Ubuntu_20.04_image_tar_with_no_vulns_shown",
			Args: []string{"", "image", "--archive",
				"--config=./testdata/ubuntu20-04-unimportant-config.toml",
				"./testdata/test-ubuntu-20-04.tar"},
			Exit: 0,
		},
		{
			// This tests that the fzf go binary is not being reported because it's a OS package
			Name: "Scanning_Ubuntu_image_with_go_OS_packages_json",
			Args: []string{"", "image", "--archive", "./testdata/test-ubuntu-with-packages.tar"},
			Exit: 1,
		},
		{
			Name: "Scanning_python_image_with_some_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-python-full.tar"},
			Exit: 1,
		},
		{
			Name: "Scanning_python_image_with_no_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-python-empty.tar"},
			Exit: 1,
		},
		{
			Name: "Scanning_java_image_with_some_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-java-full.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_node_modules_using_npm_with_no_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-node_modules-npm-empty.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_node_modules_using_npm_with_some_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-node_modules-npm-full.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_node_modules_using_yarn_with_no_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-node_modules-yarn-empty.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_node_modules_using_yarn_with_some_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-node_modules-yarn-full.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_node_modules_using_pnpm_with_no_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-node_modules-pnpm-empty.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_node_modules_using_pnpm_with_some_packages",
			Args: []string{"", "image", "--archive", "./testdata/test-node_modules-pnpm-full.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_image_with_go_binary",
			Args: []string{"", "image", "--archive", "./testdata/test-package-tracing.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_insecure_alpine_image_without_detectors",
			Args: []string{
				"", "image",
				"--archive", "./testdata/test-alpine-etcshadow.tar",
			},
			Exit: 1,
		},
		{
			Name: "scanning_insecure_alpine_image_with_specific_detector_enabled",
			Args: []string{
				"", "image",
				"--x-plugins", "os/apk",
				"--x-plugins", "weakcredentials/etcshadow",
				"--archive", "./testdata/test-alpine-etcshadow.tar",
			},
			Exit: 1,
		},
		{
			Name: "scanning_insecure_alpine_image_with_specific_detector_disabled",
			Args: []string{
				"", "image",
				"--x-plugins", "os/apk",
				"--x-plugins", "weakcreds",
				"--x-disable-plugins", "weakcredentials/etcshadow",
				"--archive", "./testdata/test-alpine-etcshadow.tar",
			},
			Exit: 1,
		},
		{
			Name: "scanning_insecure_alpine_image_with_detector_preset",
			Args: []string{
				"", "image",
				"--x-plugins", "os/apk",
				"--x-plugins", "weakcreds",
				"--archive", "./testdata/test-alpine-etcshadow.tar",
			},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// point out that we need the images to be built and saved separately
			for _, arg := range tt.Args {
				if strings.HasPrefix(arg, "./testdata/") && strings.HasSuffix(arg, ".tar") {
					if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s does not exist - have you run scripts/build_test_images.sh?", arg)
					}
				}
			}

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_OCIImage_JSONFormat(t *testing.T) {
	t.Parallel()
	testutility.SkipIfNotAcceptanceTesting(t, "Requires docker to build the images")

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		{
			Name: "Scanning_python_image_with_some_packages",
			Args: []string{"", "image", "--archive", "--format=json", "./testdata/test-python-full.tar"},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
				testutility.NormalizeHistoryCommand,
				testutility.ShortenHistoryCommandLength,
			},
		},
		{
			Name: "scanning_node_modules_using_npm_with_some_packages",
			Args: []string{"", "image", "--archive", "--format=json", "./testdata/test-node_modules-npm-full.tar"},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
				testutility.NormalizeHistoryCommand,
				testutility.ShortenHistoryCommandLength,
			},
		},
		{
			Name: "scanning_image_with_go_binary",
			Args: []string{"", "image", "--archive", "--all-packages", "--format=json", "./testdata/test-go-binary.tar"},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
				testutility.NormalizeHistoryCommand,
			},
		},
		{
			Name: "scanning_ubuntu_image",
			Args: []string{"", "image", "--archive", "--format=json", "./testdata/test-ubuntu.tar"},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
			},
		},
		{
			// This tests that the fzf go binary is not being reported because it's a OS package
			Name: "ubuntu_image_with_go_OS_packages_json",
			Args: []string{"", "image", "--archive", "--format=json", "./testdata/test-ubuntu-with-packages.tar"},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
			},
		},
		{
			Name: "scanning_insecure_alpine_image_with_specific_detector_enabled",
			Args: []string{
				"", "image", "--format=json",
				"--x-plugins", "os/apk",
				"--x-plugins", "weakcredentials/etcshadow",
				"--archive", "./testdata/test-alpine-etcshadow.tar",
			},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
			},
		},
		{
			Name: "scanning_insecure_alpine_image_with_detector_preset",
			Args: []string{
				"", "image", "--format=json",
				"--x-plugins", "os/apk",
				"--x-plugins", "weakcreds",
				"--archive", "./testdata/test-alpine-etcshadow.tar",
			},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
			},
		},
		{
			Name: "scanning_image_with_deprecated_packages",
			Args: []string{
				"", "image", "--format=json",
				"--x-flag-deprecated-packages",
				"--archive", "./testdata/test-image-with-deprecated.tar",
			},
			Exit: 1,
			ReplaceRules: []testutility.JSONReplaceRule{
				testutility.GroupsAsArrayLen,
				testutility.OnlyIDVulnsRule,
				testutility.OnlyFirstBaseImage,
				testutility.AnyDiffID,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// point out that we need the images to be built and saved separately
			for _, arg := range tt.Args {
				if strings.HasPrefix(arg, "./testdata/") && strings.HasSuffix(arg, ".tar") {
					if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s does not exist - have you run scripts/build_test_images.sh?", arg)
					}
				}
			}

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_HtmlFile(t *testing.T) {
	t.Parallel()
	testutility.SkipIfNotAcceptanceTesting(t, "Needs built container images")

	testDir := testutility.CreateTestDir(t)
	client := testcmd.InsertCassette(t)

	_, stderr := testcmd.RunAndNormalize(t, testcmd.Case{
		Name: "one_specific_supported_lockfile",
		Args: []string{"",
			"image", "--format=html", "--output-file", testDir + "/report.html",
			"--archive", "./testdata/test-alpine.tar",
		},
		Exit: 1,

		HTTPClient: testcmd.WithTestNameHeader(t, *client),
	})

	testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
		"CreateFile": "stat",
	}).MatchText(t, stderr)

	_, err := os.Stat(testDir + "/report.html")

	if err != nil {
		t.Errorf("Unexpected %v", err)
	}
}
