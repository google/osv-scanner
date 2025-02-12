package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type htmlReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func newHTMLReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *htmlReporter {
	return &htmlReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		hasErrored: false,
	}
}

func (r *htmlReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintHTMLResults(vulnResult, r.stdout)
}
