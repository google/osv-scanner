package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type JSONReporter struct {
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
}

func NewJSONReporter(stdout io.Writer, stderr io.Writer) *JSONReporter {
	return &JSONReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
	}
}

func (r *JSONReporter) PrintError(msg string) {
	r.PrintErrorf(msg)
}

func (r *JSONReporter) PrintErrorf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
	r.hasPrintedError = true
}

func (r *JSONReporter) PrintWarnf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
}

func (r *JSONReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *JSONReporter) PrintText(msg string) {
	r.PrintTextf(msg)
}

func (r *JSONReporter) PrintTextf(msg string, a ...any) {
	// Print non json text to stderr
	fmt.Fprintf(r.stderr, msg, a...)
}

func (r *JSONReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintJSONResults(vulnResult, r.stdout)
}
