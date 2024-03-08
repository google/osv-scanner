package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type SARIFReporter struct {
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
}

func NewSarifReporter(stdout io.Writer, stderr io.Writer) *SARIFReporter {
	return &SARIFReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
	}
}

func (r *SARIFReporter) PrintError(msg string) {
	r.PrintErrorf(msg)
}

func (r *SARIFReporter) PrintWarnf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
}

func (r *SARIFReporter) PrintErrorf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
	r.hasPrintedError = true
}

func (r *SARIFReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *SARIFReporter) PrintText(msg string) {
	r.PrintTextf(msg)
}

func (r *SARIFReporter) PrintTextf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
}

func (r *SARIFReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintSARIFReport(vulnResult, r.stdout)
}
