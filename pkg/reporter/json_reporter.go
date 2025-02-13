package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type jsonReporter struct {
	writer io.Writer
}

func (r *jsonReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintJSONResults(vulnResult, r.writer)
}
