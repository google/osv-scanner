package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type SBOMReporter struct {
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
}

func NewSBOMReporter(stdout io.Writer, stderr io.Writer) *SBOMReporter {
	return &SBOMReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
	}
}

func (r *SBOMReporter) PrintError(msg string) {
	fmt.Fprint(r.stderr, msg)
	r.hasPrintedError = true
}

func (r *SBOMReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *SBOMReporter) PrintText(msg string) {
	// Print non json text to stderr
	fmt.Fprint(r.stderr, msg)
}

func (r *SBOMReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintCycloneDxSbomResults(vulnResult, r.stdout)
}
