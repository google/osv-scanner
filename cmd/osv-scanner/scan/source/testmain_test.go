package source_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/source"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	// ensure a git repository doesn't already exist in the testdata directory,
	// in case we didn't get a chance to clean-up properly in the last run
	os.RemoveAll("./testdata/.git")

	// Temporarily make the testdata folder a git repository to prevent gitignore files messing with tests.
	_, err := git.PlainInit("./testdata", false)
	if err != nil {
		panic(err)
	}

	slog.SetDefault(slog.New(testlogger.New()))
	testcmd.CommandsUnderTest = []cmd.CommandBuilder{source.Command}
	m.Run()

	os.RemoveAll("./testdata/.git")

	testutility.CleanSnapshots(m)
}
