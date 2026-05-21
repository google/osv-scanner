package mcp

import (
	"fmt"
	"path/filepath"

	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scanner/v2/internal/output"
)

type fileOpenedLogger struct {
	stats.NoopCollector

	workspaceRoots []string
	collectedLines []string
}

var _ stats.Collector = &fileOpenedLogger{}

func (c *fileOpenedLogger) AfterExtractorRun(_ string, extractorstats *stats.AfterExtractorStats) {
	if extractorstats.Error != nil { // Don't log scanned if error occurred
		return
	}

	pkgsFound := len(extractorstats.Inventory.Packages)

	c.collectedLines = append(c.collectedLines,
		fmt.Sprintf(
			"Scanned %s file and found %d %s",
			redactWorkspaceRoots(filepath.Join(extractorstats.Root, extractorstats.Path), c.workspaceRoots),
			pkgsFound,
			output.Form(pkgsFound, "package", "packages"),
		))
}
