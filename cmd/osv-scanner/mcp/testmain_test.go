package mcp_test

import (
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/mcp"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	config.OSVScannerConfigName = "osv-scanner-test.toml"

	slog.SetDefault(slog.New(testlogger.New()))
	// This is technically not necessary, as we are running mcp via a subprocess
	testcmd.CommandsUnderTest = []cmd.CommandBuilder{mcp.Command}
	m.Run()

	testutility.CleanSnapshots(m)
}
