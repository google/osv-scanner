package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type sarifReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func newSarifReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *sarifReporter {
	return &sarifReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		hasErrored: false,
	}
}

func (r *sarifReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintSARIFReport(vulnResult, r.stdout)
}
