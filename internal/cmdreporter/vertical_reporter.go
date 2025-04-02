package cmdreporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/cmdoutput"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/text"
)

type verticalReporter struct {
	writer io.Writer
	// 0 indicates not a terminal output
	terminalWidth int
}

func (r *verticalReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && vulnResult.LicenseSummary == nil && !cmdlogger.HasErrored() {
		fmt.Fprintf(r.writer, "No issues found\n")
		return nil
	}

	if r.terminalWidth <= 0 {
		text.DisableColors()
	}

	cmdoutput.PrintVerticalResults(vulnResult, r.writer)

	return nil
}
