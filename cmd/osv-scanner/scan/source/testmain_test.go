package source_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	// ensure a git repository doesn't already exist in the fixtures directory,
	// in case we didn't get a chance to clean-up properly in the last run
	os.RemoveAll("./fixtures/.git")

	// Temporarily make the fixtures folder a git repository to prevent gitignore files messing with tests.
	_, err := git.PlainInit("./fixtures", false)
	if err != nil {
		panic(err)
	}

	slog.SetDefault(slog.New(testlogger.New()))
	m.Run()

	testutility.CleanSnapshots(m)

	os.RemoveAll("./fixtures/.git")
}
