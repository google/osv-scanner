package main

import (
	"os"
	"slices"
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
)

func TestRun_Update(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		args     []string
		manifest string
		exit     int
	}{
		{
			name:     "update pom.xml with in-place changes",
			args:     []string{"", "update"},
			manifest: "./update/fixtures/pom.xml",
			exit:     0,
		},
		// TODO: add other test cases.
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tc := cliTestCase{
				name: tt.name,
				args: slices.Clone(tt.args),
				exit: tt.exit,
			}

			// Update action overwrites files, copy them to a temporary directory.
			testDir := testutility.CreateTestDir(t)

			var manifest string
			if tt.manifest != "" {
				manifest = copyFileTo(t, tt.manifest, testDir)
				tc.args = append(tc.args, "-M", manifest)
			}

			stdout, stderr := runCli(t, tc)

			testutility.NewSnapshot().MatchText(t, stdout)
			testutility.NewSnapshot().MatchText(t, stderr)

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
