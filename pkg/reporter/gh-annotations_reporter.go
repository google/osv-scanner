package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type ghAnnotationsReporter struct {
	writer io.Writer
}

func (r *ghAnnotationsReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintGHAnnotationReport(vulnResult, r.writer)
}
