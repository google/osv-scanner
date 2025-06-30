package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type tableReporter struct {
	writer   io.Writer
	markdown bool
	// 0 indicates not a terminal output
	terminalWidth int
	showAllVulns  bool
}

func (r *tableReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && vulnResult.LicenseSummary == nil && !cmdlogger.HasErrored() {
		fmt.Fprintf(r.writer, "No issues found\n")
		return nil
	}

	if r.markdown {
		output.PrintMarkdownTableResults(vulnResult, r.writer, r.showAllVulns)
	} else {
		output.PrintTableResults(vulnResult, r.writer, r.terminalWidth, r.showAllVulns)
	}

	return nil
}
