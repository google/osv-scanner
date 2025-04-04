package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type spdxReporter struct {
	writer io.Writer
}

func (r *spdxReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintSPDXResults(vulnResult, r.writer)
}
