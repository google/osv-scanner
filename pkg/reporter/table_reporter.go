package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type TableReporter struct {
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
	markdown        bool
	includeSeverity bool
}

func NewTableReporter(stdout io.Writer, stderr io.Writer, markdown bool, includeSeverity bool) *TableReporter {
	return &TableReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
		markdown:        markdown,
		includeSeverity: includeSeverity,
	}
}

func (r *TableReporter) PrintError(msg string) {
	fmt.Fprint(r.stderr, msg)
	r.hasPrintedError = true
}

func (r *TableReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *TableReporter) PrintText(msg string) {
	fmt.Fprint(r.stdout, msg)
}

func (r *TableReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if len(vulnResult.Results) == 0 && !r.hasPrintedError {
		fmt.Fprintf(r.stdout, "No vulnerabilities found\n")
		return nil
	}

	if r.markdown {
		output.PrintMarkdownTableResults(vulnResult, r.stdout, r.includeSeverity)
	} else {
		output.PrintTableResults(vulnResult, r.stdout, r.includeSeverity)
	}

	return nil
}
