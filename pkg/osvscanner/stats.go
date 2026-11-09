package osvscanner

import (
	"path/filepath"

	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/output"
)

// fileOpenedPrinter tracks which files have been extracted and logs each
// scanned file, while also forwarding all stats to the embedded collector
type fileOpenedPrinter struct {
	stats.Collector

	filesExtracted map[string]struct{}
}

var _ stats.Collector = &fileOpenedPrinter{}

func newFileOpenedPrinter(collector stats.Collector) *fileOpenedPrinter {
	if collector == nil {
		collector = stats.NoopCollector{}
	}

	return &fileOpenedPrinter{
		Collector:      collector,
		filesExtracted: make(map[string]struct{}),
	}
}

func (c *fileOpenedPrinter) AfterExtractorRun(pluginName string, extractorstats *stats.AfterExtractorStats) {
	systemPath := filepath.Join(extractorstats.Root, filepath.FromSlash(extractorstats.Path))
	c.filesExtracted[systemPath] = struct{}{}

	c.Collector.AfterExtractorRun(pluginName, extractorstats)

	if extractorstats.Error != nil { // Don't log scanned if error occurred
		return
	}

	pkgsFound := len(extractorstats.Inventory.Packages)

	cmdlogger.Infof(
		"Scanned %s file and found %d %s",
		systemPath,
		pkgsFound,
		output.Form(pkgsFound, "package", "packages"),
	)
}
