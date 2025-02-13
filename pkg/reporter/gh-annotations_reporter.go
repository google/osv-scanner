package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type ghAnnotationsReporter struct {
	stdout     io.Writer
	stderr     io.Writer
}

func newGHAnnotationsReporter(stdout io.Writer, stderr io.Writer) *ghAnnotationsReporter {
	return &ghAnnotationsReporter{
		stdout:     stdout,
		stderr:     stderr,
	}
}

func (r *ghAnnotationsReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintGHAnnotationReport(vulnResult, r.stderr)
}
