package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type HTMLReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func NewHTMLReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *HTMLReporter {
	return &HTMLReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		hasErrored: false,
	}
}

func (r *HTMLReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintHTMLResults(vulnResult, r.stdout)
}
