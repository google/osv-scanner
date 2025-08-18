package source_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/source"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func setupGitFixtures() (func(), error) {
	// ensure a git repository doesn't already exist in the fixtures directory,
	// in case we didn't get a chance to clean-up properly in the last run
	os.RemoveAll("./fixtures/.git")

	toRemove := []string{"./fixtures/.git"}

	cleaner := func() {
		for _, p := range toRemove {
			os.RemoveAll(p)
		}
	}

	// Temporarily make the fixtures folder a git repository to prevent gitignore files messing with tests.
	_, err := git.PlainInit("./fixtures", false)
	if err != nil {
		return cleaner, err
	}

	for _, f := range []string{
		"./fixtures/locks-gitignore/test.gitignore",
		"./fixtures/locks-gitignore/subdir/test.gitignore",
	} {
		gitignoreFile, err := testcmd.CopyFile(f, filepath.Join(filepath.Dir(f), ".gitignore"))

		if err != nil {
			return cleaner, err
		}

		toRemove = append(toRemove, gitignoreFile)
	}

	return cleaner, nil
}

func TestMain(m *testing.M) {
	cleanupGitFixtures, err := setupGitFixtures()

	if err != nil {
		cleanupGitFixtures()

		panic(err)
	}

	slog.SetDefault(slog.New(testlogger.New()))
	testcmd.CommandsUnderTest = []cmd.CommandBuilder{source.Command}
	m.Run()

	cleanupGitFixtures()

	testutility.CleanSnapshots(m)
}
