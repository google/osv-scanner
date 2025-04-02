package cmdreporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdoutput"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type ghAnnotationsReporter struct {
	writer io.Writer
}

func (r *ghAnnotationsReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return cmdoutput.PrintGHAnnotationReport(vulnResult, r.writer)
}
