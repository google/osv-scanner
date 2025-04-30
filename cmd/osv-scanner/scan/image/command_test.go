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

func TestCommand_Docker(t *testing.T) {
	t.Parallel()

	testutility.SkipIfNotAcceptanceTesting(t, "Takes a long time to pull down images")

	tests := []testcmd.Case{
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
			Name: "Real Alpine image",
			Args: []string{"", "image", "alpine:3.18.9"},
			Exit: 1,
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

func TestCommand_OCIImageAllPackagesJSON(t *testing.T) {
	t.Parallel()

	testutility.SkipIfNotAcceptanceTesting(t, "Takes a while to run")

	if runtime.GOOS == "windows" {
		// Windows messes with the file paths to break the output
		testutility.Skip(t)
	}

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
			Name: "scanning ubuntu image in json format",
			Args: []string{"", "image", "--archive", "--format=json", "../../../../internal/image/fixtures/test-ubuntu.tar"},
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
