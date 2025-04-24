package osvscanner

import (
	"fmt"
	"log/slog"

	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scanner/v2/internal/output"
)

type FileOpenedPrinter struct {
	stats.NoopCollector
}

var _ stats.Collector = &FileOpenedPrinter{}

func (c FileOpenedPrinter) AfterExtractorRun(pluginName string, extractorstats *stats.AfterExtractorStats) {
	pkgsFound := len(extractorstats.Inventory.Packages)

	slog.Info(fmt.Sprintf(
		"Scanned %s file and found %d %s",
		extractorstats.Path,
		pkgsFound,
		output.Form(pkgsFound, "package", "packages"),
	))
}
