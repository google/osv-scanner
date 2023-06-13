package output

import (
	"io"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/jedib0t/go-pretty/v6/table"
)

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintMarkdownTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, includeSeverity bool) {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	row := table.Row{"OSV URL"}
	if includeSeverity {
		row = append(row, "Severity")
	}
	row = append(row, "Ecosystem", "Package", "Version", "Source")
	outputTable.AppendHeader(row)

	outputTable = tableBuilder(outputTable, vulnResult, false, includeSeverity)

	if outputTable.Length() == 0 {
		return
	}
	outputTable.RenderMarkdown()
}
