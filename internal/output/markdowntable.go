package output

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// PrintMarkdownTableResults prints the osv scan results into a human friendly Markdown table.
// The Markdown table uses the same format and columns as the standard table output.
func PrintMarkdownTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, showAllVulns bool) {
	text.DisableColors()

	outputResult := BuildResults(vulnResult)

	printSummary(outputResult, outputWriter)
	fmt.Fprintln(outputWriter)

	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	outputTable = tableBuilder(outputTable, outputResult, showAllVulns)

	if outputTable.Length() != 0 {
		outputTable.RenderMarkdown()
	}

	licenseConfig := vulnResult.ExperimentalAnalysisConfig.Licenses
	if licenseConfig.Summary {
		outputLicenseSummaryTable := table.NewWriter()
		outputLicenseSummaryTable.SetOutputMirror(outputWriter)
		outputLicenseSummaryTable = licenseSummaryTableBuilder(outputLicenseSummaryTable, vulnResult)

		if outputLicenseSummaryTable.Length() != 0 {
			outputLicenseSummaryTable.RenderMarkdown()
		}
	}

	if len(licenseConfig.Allowlist) > 0 {
		outputLicenseViolationsTable := table.NewWriter()
		outputLicenseViolationsTable.SetOutputMirror(outputWriter)
		outputLicenseViolationsTable = licenseViolationsTableBuilder(outputLicenseViolationsTable, vulnResult)

		if outputLicenseViolationsTable.Length() > 0 {
			outputLicenseViolationsTable.RenderMarkdown()
		}
	}
}
