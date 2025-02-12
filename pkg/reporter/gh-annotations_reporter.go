package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type GHAnnotationsReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func NewGHAnnotationsReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *GHAnnotationsReporter {
	return &GHAnnotationsReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		hasErrored: false,
	}
}

func (r *GHAnnotationsReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintGHAnnotationReport(vulnResult, r.stderr)
}
