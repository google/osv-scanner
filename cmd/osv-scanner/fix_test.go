package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
)

func copyFileTo(t *testing.T, file, dir string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("could not read test file: %v", err)
	}

	dst := filepath.Join(dir, filepath.Base(file))
	if err := os.WriteFile(dst, b, 0600); err != nil {
		t.Fatalf("could not copy test file: %v", err)
	}

	return dst
}

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
			lockfile: "./fix/fixtures/in-place-npm/package-lock.json",
		},
		{
			name:     "fix non-interactive relax package.json",
			args:     []string{"", "fix", "--strategy=relax"},
			exit:     0,
			manifest: "./fix/fixtures/relax-npm/package.json",
		},
		{
			name:     "fix non-interactive override pom.xml",
			args:     []string{"", "fix", "--strategy=override"},
			exit:     0,
			manifest: "./fix/fixtures/override-maven/pom.xml",
		},
		{
			name:     "fix non-interactive json in-place package-lock.json",
			args:     []string{"", "fix", "--strategy=in-place", "--format=json"},
			exit:     0,
			lockfile: "./fix/fixtures/in-place-npm/package-lock.json",
		},
		{
			name:     "fix non-interactive json relax package.json",
			args:     []string{"", "fix", "--strategy=relax", "--format=json"},
			exit:     0,
			manifest: "./fix/fixtures/relax-npm/package.json",
		},
		{
			name:     "fix non-interactive json override pom.xml",
			args:     []string{"", "fix", "--strategy=override", "--format=json"},
			exit:     0,
			manifest: "./fix/fixtures/override-maven/pom.xml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := cliTestCase{
				name: tt.name,
				args: slices.Clone(tt.args),
				exit: tt.exit,
			}

			// fix action overwrites files, copy them to a temporary directory
			testDir := testutility.CreateTestDir(t)

			var lockfile, manifest string
			if tt.lockfile != "" {
				lockfile = copyFileTo(t, tt.lockfile, testDir)
				tc.args = append(tc.args, "-L", lockfile)
			}
			if tt.manifest != "" {
				manifest = copyFileTo(t, tt.manifest, testDir)
				tc.args = append(tc.args, "-M", manifest)
			}

			stdout, stderr := runCli(t, tc)

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
