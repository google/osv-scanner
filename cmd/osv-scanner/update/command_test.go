package update_test

import (
	"os"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestCommand(t *testing.T) {
	t.Parallel()

	tests := []testcmd.Case{
		{
			Name: "update pom.xml with in-place changes",
			Args: []string{"", "update", "-M=./fixtures/pom.xml"},
			Exit: 0,
		},
		{
			Name: "update_pom_with_in_place_changes_using_deps_dev_data_source",
			Args: []string{"", "update", "--data-source", "deps.dev", "-M", "./fixtures/pom.xml"},
			Exit: 0,
		},
		{
			Name: "update_pom_with_in_place_changes_using_native_data_source",
			Args: []string{"", "update", "--data-source", "native", "-M", "./fixtures/pom.xml"},
			Exit: 0,
		},
		{
			Name: "errors_with_invalid_data_source",
			Args: []string{"", "update", "--data-source", "github", "-M", "./fixtures/pom.xml"},
			Exit: 127,
		},
		{
			Name: "file_does_not_exist",
			Args: []string{"", "update", "-M", "./fixtures/does_not_exist.xml"},
			Exit: 127,
		},
		// TODO: add other test cases.
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// Update action overwrites files, copy them to a temporary directory.
			testDir := testutility.CreateTestDir(t)

			manifest := testcmd.CopyFileFlagTo(t, tt, "-M", testDir)

			testcmd.RunAndMatchSnapshots(t, tt)

			if manifest != "" {
				b, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatalf("could not read test file: %v", err)
				}
				testutility.NewSnapshot().WithCRLFReplacement().MatchText(t, string(b))
			}
		})
	}
}
