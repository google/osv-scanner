package output

import (
	"io"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// PrintMarkdownTableResults prints the osv scan results into a human friendly table.
func PrintMarkdownTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	text.DisableColors()

	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	outputTable = tableBuilder(outputTable, vulnResult)

	if outputTable.Length() != 0 {
		outputTable.RenderMarkdown()
	}

	outputLicenseTable := table.NewWriter()
	outputLicenseTable.SetOutputMirror(outputWriter)

	licenseConfig := vulnResult.ExperimentalAnalysisConfig.Licenses
	if licenseConfig.Summary {
		outputLicenseSummaryTable := table.NewWriter()
		outputLicenseSummaryTable = licenseSummaryTableBuilder(outputLicenseSummaryTable, vulnResult)

		if outputLicenseSummaryTable.Length() != 0 {
			outputLicenseSummaryTable.RenderMarkdown()
		}
	}

	if len(licenseConfig.Allowlist) > 0 {
		outputLicenseViolationsTable := table.NewWriter()
		outputLicenseViolationsTable = licenseViolationsTableBuilder(outputLicenseViolationsTable, vulnResult)

		if outputLicenseViolationsTable.Length() != 0 {
			outputLicenseViolationsTable.RenderMarkdown()
		}
	}
}
