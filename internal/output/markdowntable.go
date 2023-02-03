package output

import (
	"io"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/jedib0t/go-pretty/v6/table"
)

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintMarkdownTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	outputTable.AppendHeader(table.Row{"OSV URL", "Ecosystem", "Package", "Version", "Source"})

	outputTable = tableBuilder(outputTable, vulnResult, false)

	if outputTable.Length() == 0 {
		return
	}
	outputTable.RenderMarkdown()
}
