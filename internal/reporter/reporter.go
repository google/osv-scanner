// Package reporter provides functionality for reporting scan results in various formats.
package reporter

import (
	"io"

	"github.com/google/osv-scanner/v2/pkg/models"
)

type resultPrinter interface {
	// PrintResult prints the models.VulnerabilityResults per the logic of the
	// actual reporter
	PrintResult(vulnResult *models.VulnerabilityResults) error
}

func PrintResult(
	vulnResult *models.VulnerabilityResults,
	format string,
	writer io.Writer,
	terminalWidth int,
	showAllVulns bool,
) error {
	r, err := newResultPrinter(format, writer, terminalWidth, showAllVulns)

	if err != nil {
		return err
	}

	return r.PrintResult(vulnResult)
}
