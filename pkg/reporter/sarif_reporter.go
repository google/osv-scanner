package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type sarifReporter struct {
	writer io.Writer
}

func (r *sarifReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintSARIFReport(vulnResult, r.writer)
}
