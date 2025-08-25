package image_test

import (
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/image"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(testlogger.New()))
	testcmd.CommandsUnderTest = []cmd.CommandBuilder{image.Command}
	m.Run()

	testutility.CleanSnapshots(m)
}
