package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
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
	testutility.NewSnapshot().WithWindowsReplacements(map[string]string{"\r\n": "\n"}).MatchText(t, string(b))
}

func TestRun_Fix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		args     []string
		exit     int
		manifest string
		lockfile string
	}{
		{
			name:     "fix non-interactive in-place package-lock.json",
			args:     []string{"", "fix", "--non-interactive", "--strategy=in-place"},
			exit:     0,
			lockfile: "./fix/fixtures/in-place-npm/package-lock.json",
		},
		{
			name:     "fix non-interactive relock package.json",
			args:     []string{"", "fix", "--non-interactive", "--strategy=relock"},
			exit:     0,
			manifest: "./fix/fixtures/relock-npm/package.json",
		},
		// TODO: add tests with the cli flags
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

			// fix action overwrites files, copy them to a temporary directory
			testDir, cleanupTestDir := createTestDir(t)
			defer cleanupTestDir()

			var lockfile, manifest string
			if tt.lockfile != "" {
				lockfile = copyFileTo(t, tt.lockfile, testDir)
				tc.args = append(tc.args, "-L", lockfile)
			}
			if tt.manifest != "" {
				manifest = copyFileTo(t, tt.manifest, testDir)
				tc.args = append(tc.args, "-M", manifest)
			}

			testCli(t, tc)
			if lockfile != "" {
				matchFile(t, lockfile)
			}
			if manifest != "" {
				matchFile(t, manifest)
			}
		})
	}
}
