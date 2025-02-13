package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// jsonReporter prints vulnerability results in JSON format to stdout. Runtime information
// will be written to stderr.
type jsonReporter struct {
	stdout     io.Writer
	stderr     io.Writer
}

func newJSONReporter(stdout io.Writer, stderr io.Writer) *jsonReporter {
	return &jsonReporter{
		stdout:     stdout,
		stderr:     stderr,
	}
}

func (r *jsonReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintJSONResults(vulnResult, r.stdout)
}
