package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type ghAnnotationsReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func newGHAnnotationsReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *ghAnnotationsReporter {
	return &ghAnnotationsReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		hasErrored: false,
	}
}

func (r *ghAnnotationsReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintGHAnnotationReport(vulnResult, r.stderr)
}
