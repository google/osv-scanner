package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/pkg/models"
)

var format = []string{"table", "html", "vertical", "json", "markdown", "sarif", "gh-annotations", "cyclonedx-1-4", "cyclonedx-1-5"}

func Format() []string {
	return format
}

func newResultPrinter(format string, stdout, stderr io.Writer, level VerbosityLevel, terminalWidth int) (resultPrinter, error) {
	switch format {
	case "html":
		return newHTMLReporter(stdout, stderr, level), nil
	case "json":
		return newJSONReporter(stdout, stderr, level), nil
	case "vertical":
		return newVerticalReporter(stdout, stderr, level, false, terminalWidth), nil
	case "table":
		return newTableReporter(stdout, stderr, level, false, terminalWidth), nil
	case "markdown":
		return newTableReporter(stdout, stderr, level, true, terminalWidth), nil
	case "sarif":
		return newSarifReporter(stdout, stderr, level), nil
	case "gh-annotations":
		return newGHAnnotationsReporter(stdout, stderr, level), nil
	case "cyclonedx-1-4":
		return newCycloneDXReporter(stdout, stderr, models.CycloneDXVersion14, level), nil
	case "cyclonedx-1-5":
		return newCycloneDXReporter(stdout, stderr, models.CycloneDXVersion15, level), nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
