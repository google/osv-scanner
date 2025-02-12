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
		return NewHTMLReporter(stdout, stderr, level), nil
	case "json":
		return NewJSONReporter(stdout, stderr, level), nil
	case "vertical":
		return NewVerticalReporter(stdout, stderr, level, false, terminalWidth), nil
	case "table":
		return NewTableReporter(stdout, stderr, level, false, terminalWidth), nil
	case "markdown":
		return NewTableReporter(stdout, stderr, level, true, terminalWidth), nil
	case "sarif":
		return NewSarifReporter(stdout, stderr, level), nil
	case "gh-annotations":
		return NewGHAnnotationsReporter(stdout, stderr, level), nil
	case "cyclonedx-1-4":
		return NewCycloneDXReporter(stdout, stderr, models.CycloneDXVersion14, level), nil
	case "cyclonedx-1-5":
		return NewCycloneDXReporter(stdout, stderr, models.CycloneDXVersion15, level), nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
