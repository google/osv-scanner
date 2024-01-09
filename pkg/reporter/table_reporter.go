package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type TableReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
	markdown   bool
	// 0 indicates not a terminal output
	terminalWidth int
}

func NewTableReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel, markdown bool, terminalWidth int) *TableReporter {
	return &TableReporter{
		stdout:        stdout,
		stderr:        stderr,
		hasErrored:    false,
		level:         level,
		markdown:      markdown,
		terminalWidth: terminalWidth,
	}
}

func (r *TableReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(r.stderr, format, a...)
	r.hasErrored = true
}

func (r *TableReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *TableReporter) Warnf(format string, a ...any) {
	if WarnLevel <= r.level {
		fmt.Fprintf(r.stdout, format, a...)
	}
}

func (r *TableReporter) Infof(format string, a ...any) {
	if InfoLevel <= r.level {
		fmt.Fprintf(r.stdout, format, a...)
	}
}

func (r *TableReporter) Verbosef(format string, a ...any) {
	if VerboseLevel <= r.level {
		fmt.Fprintf(r.stdout, format, a...)
	}
}

func (r *TableReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && !r.hasErrored {
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
