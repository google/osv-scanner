package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type htmlReporter struct {
	writer io.Writer
}

func newHTMLReporter(writer io.Writer) *htmlReporter {
	return &htmlReporter{
		writer: writer,
	}
}

func (r *htmlReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintHTMLResults(vulnResult, r.writer)
}
