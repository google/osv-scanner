package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type tableReporter struct {
	stdout     io.Writer
	stderr     io.Writer
	markdown   bool
	// 0 indicates not a terminal output
	terminalWidth int
}

func newTableReporter(stdout io.Writer, stderr io.Writer, markdown bool, terminalWidth int) *tableReporter {
	return &tableReporter{
		stdout:        stdout,
		stderr:        stderr,
		markdown:      markdown,
		terminalWidth: terminalWidth,
	}
}

func (r *tableReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && vulnResult.LicenseSummary == nil {
		fmt.Fprintf(r.stdout, "No issues found\n")
		return nil
	}

	if r.markdown {
		output.PrintMarkdownTableResults(vulnResult, r.stdout)
	} else {
		output.PrintTableResults(vulnResult, r.stdout, r.terminalWidth)
	}

	return nil
}
