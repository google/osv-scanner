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
	stdout, stderr io.Writer,
	terminalWidth int,
) error {
	r, err := newResultPrinter(format, stdout, stderr, terminalWidth)

	if err != nil {
		return err
	}

	return r.PrintResult(vulnResult)
}
