package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type MarkdownReporter struct {
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
}

func NewMarkdownReporter(stdout io.Writer, stderr io.Writer) *MarkdownReporter {
	return &MarkdownReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
	}
}

func (r *MarkdownReporter) PrintError(msg string) {
	fmt.Fprint(r.stderr, msg)
	r.hasPrintedError = true
}

func (r *MarkdownReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *MarkdownReporter) PrintText(msg string) {
	fmt.Fprint(r.stdout, msg)
}

func (r *MarkdownReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && !r.hasPrintedError {
		fmt.Fprintf(r.stdout, "No vulnerabilities found\n")
		return nil
	}

	output.PrintMarkdownTextResults(vulnResult, r.stdout)

	return nil
}
