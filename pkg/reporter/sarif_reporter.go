package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type sarifReporter struct {
	stdout     io.Writer
	stderr     io.Writer
}

func newSarifReporter(stdout io.Writer, stderr io.Writer) *sarifReporter {
	return &sarifReporter{
		stdout:     stdout,
		stderr:     stderr,
	}
}

func (r *sarifReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintSARIFReport(vulnResult, r.stdout)
}
