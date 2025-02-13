package reporter

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/google/osv-scanner/v2/internal/output"

	"github.com/google/osv-scanner/v2/pkg/models"
)

type cycloneDXReporter struct {
	writer  io.Writer
	version models.CycloneDXVersion
}

func newCycloneDXReporter(writer io.Writer, version models.CycloneDXVersion) *cycloneDXReporter {
	return &cycloneDXReporter{
		writer:  writer,
		version: version,
	}
}

func (r *cycloneDXReporter) PrintResult(vulnerabilityResults *models.VulnerabilityResults) error {
	errs := output.PrintCycloneDXResults(vulnerabilityResults, r.version, r.writer)
	if errs != nil {
		for _, err := range strings.Split(errs.Error(), "\n") {
			slog.Warn(fmt.Sprintf("Failed to parse package URL: %v", err))
		}
	}

	return nil
}
