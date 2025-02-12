package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/text"
)

type verticalReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
	markdown   bool
	// 0 indicates not a terminal output
	terminalWidth int
}

func newVerticalReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel, markdown bool, terminalWidth int) *verticalReporter {
	return &verticalReporter{
		stdout:        stdout,
		stderr:        stderr,
		hasErrored:    false,
		level:         level,
		markdown:      markdown,
		terminalWidth: terminalWidth,
	}
}

func (r *verticalReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && vulnResult.LicenseSummary == nil && !r.hasErrored {
		fmt.Fprintf(r.stdout, "No issues found\n")
		return nil
	}

	if r.terminalWidth <= 0 {
		text.DisableColors()
	}

	output.PrintVerticalResults(vulnResult, r.stdout)

	return nil
}
