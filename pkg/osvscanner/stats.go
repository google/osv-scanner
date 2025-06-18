package osvscanner

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scanner/v2/internal/output"
)

type FileOpenedPrinter struct {
	stats.NoopCollector
}

var _ stats.Collector = &FileOpenedPrinter{}

func (c FileOpenedPrinter) AfterExtractorRun(_ string, extractorstats *stats.AfterExtractorStats) {
	if extractorstats.Error != nil { // Don't log scanned if error occurred
		return
	}

	pkgsFound := len(extractorstats.Inventory.Packages)

	slog.Info(fmt.Sprintf(
		"Scanned %s file and found %d %s",
		filepath.Join(extractorstats.Root, extractorstats.Path),
		pkgsFound,
		output.Form(pkgsFound, "package", "packages"),
	))
}
