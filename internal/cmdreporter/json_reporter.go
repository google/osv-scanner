package cmdreporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdoutput"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type jsonReporter struct {
	writer io.Writer
}

func (r *jsonReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return cmdoutput.PrintJSONResults(vulnResult, r.writer)
}
