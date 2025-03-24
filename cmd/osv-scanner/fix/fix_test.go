package fix_test

import (
	"os"
	"slices"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func matchFile(t *testing.T, file string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("could not read test file: %v", err)
	}
	testutility.NewSnapshot().WithCRLFReplacement().MatchText(t, string(b))
}

func Test_run_Fix(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		exit     int
		manifest string
		lockfile string
	}{
		{
			name:     "fix non-interactive in-place package-lock.json",
			args:     []string{"", "fix", "--strategy=in-place"},
			exit:     0,
			lockfile: "./fixtures/in-place-npm/package-lock.json",
		},
		{
			name:     "fix non-interactive relax package.json",
			args:     []string{"", "fix", "--strategy=relax"},
			exit:     0,
			manifest: "./fixtures/relax-npm/package.json",
		},
		{
			name:     "fix non-interactive override pom.xml",
			args:     []string{"", "fix", "--strategy=override"},
			exit:     0,
			manifest: "./fixtures/override-maven/pom.xml",
		},
		{
			name:     "fix non-interactive json in-place package-lock.json",
			args:     []string{"", "fix", "--strategy=in-place", "--format=json"},
			exit:     0,
			lockfile: "./fixtures/in-place-npm/package-lock.json",
		},
		{
			name:     "fix non-interactive json relax package.json",
			args:     []string{"", "fix", "--strategy=relax", "--format=json"},
			exit:     0,
			manifest: "./fixtures/relax-npm/package.json",
		},
		{
			name:     "fix non-interactive json override pom.xml",
			args:     []string{"", "fix", "--strategy=override", "--format=json"},
			exit:     0,
			manifest: "./fixtures/override-maven/pom.xml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testcmd.Case{
				Name: tt.name,
				Args: slices.Clone(tt.args),
				Exit: tt.exit,
			}

			// fix action overwrites files, copy them to a temporary directory
			testDir := testutility.CreateTestDir(t)

			var lockfile, manifest string
			if tt.lockfile != "" {
				lockfile = testcmd.CopyFileTo(t, tt.lockfile, testDir)
				tc.Args = append(tc.Args, "-L", lockfile)
			}
			if tt.manifest != "" {
				manifest = testcmd.CopyFileTo(t, tt.manifest, testDir)
				tc.Args = append(tc.Args, "-M", manifest)
			}

			stdout, stderr := testcmd.Run(t, tc)

			testutility.NewSnapshot().MatchText(t, stdout)
			testutility.NewSnapshot().MatchText(t, stderr)

			if lockfile != "" {
				matchFile(t, lockfile)
			}
			if manifest != "" {
				matchFile(t, manifest)
			}
		})
	}
}
