package update_test

import (
	"os"
	"slices"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		manifest string
		exit     int
	}{
		{
			name:     "update pom.xml with in-place changes",
			args:     []string{"", "update"},
			manifest: "./fixtures/pom.xml",
			exit:     0,
		},
		// TODO: add other test cases.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testcmd.Case{
				Name: tt.name,
				Args: slices.Clone(tt.args),
				Exit: tt.exit,
			}

			// Update action overwrites files, copy them to a temporary directory.
			testDir := testutility.CreateTestDir(t)

			var manifest string
			if tt.manifest != "" {
				manifest = testcmd.CopyFileTo(t, tt.manifest, testDir)
				tc.Args = append(tc.Args, "-M", manifest)
			}

			testcmd.Run(t, tc)

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
