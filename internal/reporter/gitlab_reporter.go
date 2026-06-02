package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

type gitlabReporter struct {
	writer io.Writer
}

func (r *gitlabReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintGitLabResults(vulnResult, r.writer)
}
