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
	outputTable = tableBuilder(outputTable, vulnResult, false)

	if outputTable.Length() != 0 {
		outputTable.RenderMarkdown()
	}

	outputLicenseTable := table.NewWriter()
	outputLicenseTable.SetOutputMirror(outputWriter)

	outputLicenseTable = licenseTableBuilder(outputLicenseTable, vulnResult)

	if outputLicenseTable.Length() == 0 {
		return
	}
	outputLicenseTable.RenderMarkdown()
}
