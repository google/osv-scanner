package cmdreporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdoutput"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type htmlReporter struct {
	writer io.Writer
}

func (r *htmlReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return cmdoutput.PrintHTMLResults(vulnResult, r.writer)
}
