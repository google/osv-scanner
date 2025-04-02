package cmdreporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdoutput"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type sarifReporter struct {
	writer io.Writer
}

func (r *sarifReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return cmdoutput.PrintSARIFReport(vulnResult, r.writer)
}
