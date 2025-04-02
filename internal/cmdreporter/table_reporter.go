package cmdreporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/cmdoutput"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type tableReporter struct {
	writer   io.Writer
	markdown bool
	// 0 indicates not a terminal output
	terminalWidth int
}

func (r *tableReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && vulnResult.LicenseSummary == nil && !cmdlogger.HasErrored() {
		fmt.Fprintf(r.writer, "No issues found\n")
		return nil
	}

	if r.markdown {
		cmdoutput.PrintMarkdownTableResults(vulnResult, r.writer)
	} else {
		cmdoutput.PrintTableResults(vulnResult, r.writer, r.terminalWidth)
	}

	return nil
}
