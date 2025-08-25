package source_test

import (
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/source"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	config.OSVScannerConfigName = "osv-scanner-test.toml"

	cleanupGitFixtures, err := testcmd.SetupGitFixtures()

	if err != nil {
		cleanupGitFixtures()

		panic(err)
	}

	slog.SetDefault(slog.New(testlogger.New()))
	testcmd.CommandsUnderTest = []cmd.CommandBuilder{source.Command}
	m.Run()

	cleanupGitFixtures()

	testcmd.SortCassetteInteractions()

	testutility.CleanSnapshots(m)
}
