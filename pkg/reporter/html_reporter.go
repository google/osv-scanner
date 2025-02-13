package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type htmlReporter struct {
	stdout     io.Writer
	stderr     io.Writer
}

func newHTMLReporter(stdout io.Writer, stderr io.Writer) *htmlReporter {
	return &htmlReporter{
		stdout:     stdout,
		stderr:     stderr,
	}
}

func (r *htmlReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintHTMLResults(vulnResult, r.stdout)
}
