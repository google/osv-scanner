package mcp

import (
	"fmt"
	"path/filepath"

	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type fileOpenedLogger struct {
	stats.NoopCollector

	ignore         *ignoreFilter
	collectedLines []string
}

var _ stats.Collector = &fileOpenedLogger{}

func (c *fileOpenedLogger) AfterExtractorRun(_ string, extractorstats *stats.AfterExtractorStats) {
	if extractorstats.Error != nil { // Don't log scanned if error occurred
		return
	}

	fullPath := filepath.Join(extractorstats.Root, extractorstats.Path)
	if c.ignore != nil && c.ignore.matchesSourcePath(models.SourceInfo{
		Path: fullPath,
		Type: models.SourceTypeProjectPackage,
	}) {
		return
	}

	pkgsFound := len(extractorstats.Inventory.Packages)

	c.collectedLines = append(c.collectedLines,
		fmt.Sprintf(
			"Scanned %s file and found %d %s",
			fullPath,
			pkgsFound,
			output.Form(pkgsFound, "package", "packages"),
		))
}
