package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// jsonReporter prints vulnerability results in JSON format to stdout. Runtime information
// will be written to stderr.
type jsonReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func newJSONReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *jsonReporter {
	return &jsonReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		hasErrored: false,
	}
}

func (r *jsonReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintJSONResults(vulnResult, r.stdout)
}
