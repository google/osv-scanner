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

func TestCommand_ExplicitExtractors(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "extractors_cancelled_out",
			Args: []string{
				"", "image",
				"--experimental-extractors=sbom/spdx",
				"--experimental-extractors=sbom/cdx",
				"--experimental-disable-extractors=sbom",
				"alpine:non-existent-tag",
			},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out_with_presets",
			Args: []string{
				"", "image",
				"--experimental-extractors=sbom",
				"--experimental-disable-extractors=sbom",
				"alpine:non-existent-tag",
			},
			Exit: 127,
		},
		{
			Name: "extractors_cancelled_out",
			Args: []string{
				"", "image",
				"--experimental-extractors=sbom/spdx,sbom/cdx",
				"--experimental-disable-extractors=sbom",
				"alpine:non-existent-tag",
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

func TestCommand_Docker(t *testing.T) {
	t.Parallel()

	testutility.SkipIfNotAcceptanceTesting(t, "Takes a long time to pull down images")

	tests := []testcmd.Case{
		{
			Name: "no_image_argument",
			Args: []string{"", "image"},
			Exit: 127,
		},
		{
			Name: "Fake alpine image",
			Args: []string{"", "image", "alpine:non-existent-tag"},
			Exit: 127,
		},
		{
			Name: "Fake image entirely",
			Args: []string{"", "image", "this-image-definitely-does-not-exist-abcde:with-tag"},
			Exit: 127,
		},
		{
			Name: "Real empty image with no tag, invalid scan target",
			Args: []string{"", "image", "hello-world"},
			Exit: 127, // Invalid scan target
		},
		{
			Name: "Real empty image with tag",
			Args: []string{"", "image", "hello-world:linux"},
			Exit: 128, // No package found
		},
		{
			Name: "real_empty_image_with_tag_and_allow_no_lockfiles_flag",
			Args: []string{"", "image", "--allow-no-lockfiles", "hello-world:linux"},
			Exit: 0,
		},
		{
			Name: "Real Alpine image",
			Args: []string{"", "image", "alpine:3.18.9"},
			Exit: 1,
		},
		{
			// this will result in an error about not being able to find any package sources
			// since we've requested the os/apk extractor disabled, and there's nothing else
			// in the image that we support extracting
			Name: "real_alpine_image_without_apk_extractor_enabled",
			Args: []string{"", "image", "--experimental-disable-extractors=os/apk", "alpine:3.18.9"},
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

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_OCIImage(t *testing.T) {
	t.Parallel()

	testutility.SkipIfNotAcceptanceTesting(t, "Takes a while to run")

	tests := []testcmd.Case{
		{
			Name: "Invalid path",
			Args: []string{"", "image", "--archive", "../../fixtures/locks-manyoci-image/no-file-here.tar"},
			Exit: 127,
		},
		{
			Name: "Alpine 3.10 image tar with 3.18 version file",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-alpine.tar"},
			Exit: 1,
		},
		{
			Name: "Empty Ubuntu 22.04 image tar",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-ubuntu.tar"},
			Exit: 1,
		},
		{
			Name: "Empty Ubuntu 22.04 image tar with unimportant vulns",
			Args: []string{"", "image", "--all-vulns", "--archive", "../../../../internal/image/fixtures/test-ubuntu.tar"},
			Exit: 1,
		},
		{
			Name: "Empty Ubuntu 20.04 image tar with only unimportant vulns shown",
			Args: []string{"", "image", "--archive", "--all-vulns",
				"--config=../../../../internal/image/fixtures/ubuntu20-04-unimportant-config.toml",
				"--all-vulns", "../../../../internal/image/fixtures/test-ubuntu-20-04.tar"},
			Exit: 1,
		},
		{
			Name: "Empty Ubuntu 20.04 image tar with no vulns shown",
			Args: []string{"", "image", "--archive",
				"--config=../../../../internal/image/fixtures/ubuntu20-04-unimportant-config.toml",
				"../../../../internal/image/fixtures/test-ubuntu-20-04.tar"},
			Exit: 0,
		},
		{
			Name: "Scanning python image with some packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-python-full.tar"},
			Exit: 1,
		},
		{
			Name: "Scanning python image with no packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-python-empty.tar"},
			Exit: 1,
		},
		{
			Name: "Scanning java image with some packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-java-full.tar"},
			Exit: 1,
		},
		{
			Name: "scanning node_modules using npm with no packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-node_modules-npm-empty.tar"},
			Exit: 1,
		},
		{
			Name: "scanning node_modules using npm with some packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-node_modules-npm-full.tar"},
			Exit: 1,
		},
		{
			Name: "scanning node_modules using yarn with no packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-node_modules-yarn-empty.tar"},
			Exit: 1,
		},
		{
			Name: "scanning node_modules using yarn with some packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-node_modules-yarn-full.tar"},
			Exit: 1,
		},
		{
			Name: "scanning node_modules using pnpm with no packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-node_modules-pnpm-empty.tar"},
			Exit: 1,
		},
		{
			Name: "scanning node_modules using pnpm with some packages",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-node_modules-pnpm-full.tar"},
			Exit: 1,
		},
		{
			Name: "scanning image with go binary",
			Args: []string{"", "image", "--archive", "../../../../internal/image/fixtures/test-package-tracing.tar"},
			Exit: 1,
		},
		{
			Name: "scanning_insecure_alpine_image_without_detectors",
			Args: []string{
				"", "image",
				"--archive", "../../../../internal/image/fixtures/test-alpine-etcshadow.tar",
			},
			Exit: 1,
		},
		{
			Name: "scanning_insecure_alpine_image_with_specific_detector_enabled",
			Args: []string{
				"", "image",
				"--experimental-detectors", "weakcredentials/etcshadow",
				"--archive", "../../../../internal/image/fixtures/test-alpine-etcshadow.tar",
			},
			Exit: 1,
		},
		{
			Name: "scanning_insecure_alpine_image_with_specific_detector_disabled",
			Args: []string{
				"", "image",
				"--experimental-detectors", "weakcreds",
				"--experimental-disable-detectors", "weakcredentials/etcshadow",
				"--archive", "../../../../internal/image/fixtures/test-alpine-etcshadow.tar",
			},
			Exit: 1,
		},
		{
			Name: "scanning_insecure_alpine_image_with_detector_preset",
			Args: []string{
				"", "image",
				"--experimental-detectors", "weakcreds",
				"--archive", "../../../../internal/image/fixtures/test-alpine-etcshadow.tar",
			},
			Exit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// point out that we need the images to be built and saved separately
			for _, arg := range tt.Args {
				if strings.HasPrefix(arg, "../../../../internal/image/fixtures/") && strings.HasSuffix(arg, ".tar") {
					if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s does not exist - have you run scripts/build_test_images.sh?", arg)
					}
				}
			}

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_OCIImage_JSONFormat(t *testing.T) {
	t.Parallel()

	testutility.SkipIfNotAcceptanceTesting(t, "Takes a while to run")

	tests := []testcmd.Case{
		{
			Name: "Scanning python image with some packages",
			Args: []string{"", "image", "--archive", "--format=json", "../../../../internal/image/fixtures/test-python-full.tar"},
			Exit: 1,
			ReplaceRules: []testcmd.JSONReplaceRule{
				testcmd.GroupsAsArrayLen,
				testcmd.OnlyIDVulnsRule,
				testcmd.OnlyFirstBaseImage,
				testcmd.AnyDiffID,
				testcmd.NormalizeHistoryCommand,
				testcmd.ShortenHistoryCommandLength,
			},
		},
		{
			Name: "scanning node_modules using npm with some packages",
			Args: []string{"", "image", "--archive", "--format=json", "../../../../internal/image/fixtures/test-node_modules-npm-full.tar"},
			Exit: 1,
			ReplaceRules: []testcmd.JSONReplaceRule{
				testcmd.GroupsAsArrayLen,
				testcmd.OnlyIDVulnsRule,
				testcmd.OnlyFirstBaseImage,
				testcmd.AnyDiffID,
				testcmd.NormalizeHistoryCommand,
				testcmd.ShortenHistoryCommandLength,
			},
		},
		{
			Name: "scanning image with go binary",
			Args: []string{"", "image", "--archive", "--all-packages", "--format=json", "../../../../internal/image/fixtures/test-go-binary.tar"},
			Exit: 1,
			ReplaceRules: []testcmd.JSONReplaceRule{
				testcmd.GroupsAsArrayLen,
				testcmd.OnlyIDVulnsRule,
				testcmd.OnlyFirstBaseImage,
				testcmd.AnyDiffID,
				testcmd.NormalizeHistoryCommand,
			},
		},
		{
			Name: "scanning ubuntu image",
			Args: []string{"", "image", "--archive", "--format=json", "../../../../internal/image/fixtures/test-ubuntu.tar"},
			Exit: 1,
			ReplaceRules: []testcmd.JSONReplaceRule{
				testcmd.GroupsAsArrayLen,
				testcmd.OnlyIDVulnsRule,
				testcmd.OnlyFirstBaseImage,
				testcmd.AnyDiffID,
			},
		},
		{
			Name: "scanning_insecure_alpine_image_with_specific_detector_enabled",
			Args: []string{
				"", "image", "--format=json",
				"--experimental-detectors", "weakcredentials/etcshadow",
				"--archive", "../../../../internal/image/fixtures/test-alpine-etcshadow.tar",
			},
			Exit: 1,
			ReplaceRules: []testcmd.JSONReplaceRule{
				testcmd.GroupsAsArrayLen,
				testcmd.OnlyIDVulnsRule,
				testcmd.OnlyFirstBaseImage,
				testcmd.AnyDiffID,
			},
		},
		{
			Name: "scanning_insecure_alpine_image_with_detector_preset",
			Args: []string{
				"", "image", "--format=json",
				"--experimental-detectors", "weakcreds",
				"--archive", "../../../../internal/image/fixtures/test-alpine-etcshadow.tar",
			},
			Exit: 1,
			ReplaceRules: []testcmd.JSONReplaceRule{
				testcmd.GroupsAsArrayLen,
				testcmd.OnlyIDVulnsRule,
				testcmd.OnlyFirstBaseImage,
				testcmd.AnyDiffID,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// point out that we need the images to be built and saved separately
			for _, arg := range tt.Args {
				if strings.HasPrefix(arg, "../../../../internal/image/fixtures/") && strings.HasSuffix(arg, ".tar") {
					if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s does not exist - have you run scripts/build_test_images.sh?", arg)
					}
				}
			}

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func TestCommand_HtmlFile(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	_, stderr := testcmd.RunAndNormalize(t, testcmd.Case{
		Name: "one specific supported lockfile",
		Args: []string{"",
			"image", "--format=html", "--output", testDir + "/report.html",
			"--archive", "../../../../internal/image/fixtures/test-alpine.tar",
		},
		Exit: 1,
	})

	testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
		"CreateFile": "stat",
	}).MatchText(t, stderr)

	_, err := os.Stat(testDir + "/report.html")

	if err != nil {
		t.Errorf("Unexpected %v", err)
	}
}
