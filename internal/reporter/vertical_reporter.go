package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/text"
)

type verticalReporter struct {
	writer io.Writer
	// 0 indicates not a terminal output
	terminalWidth int
	showAllVulns  bool
}

func (r *verticalReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && vulnResult.LicenseSummary == nil && !cmdlogger.HasErrored() {
		fmt.Fprintf(r.writer, "No issues found\n")
		return nil
	}

	if r.terminalWidth <= 0 {
		text.DisableColors()
	}

	output.PrintVerticalResults(vulnResult, r.writer, r.showAllVulns)

	return nil
}
