package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/osvdiet"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type jsonReporter struct {
	writer     io.Writer
	dietClient *osvdiet.Client
}

func (r *jsonReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintJSONResults(vulnResult, r.writer, r.dietClient)
}
