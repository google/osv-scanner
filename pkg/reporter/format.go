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

func newResultPrinter(format string, writer io.Writer, terminalWidth int) (resultPrinter, error) {
	switch format {
	case "html":
		return newHTMLReporter(writer), nil
	case "json":
		return newJSONReporter(writer), nil
	case "vertical":
		return newVerticalReporter(writer, false, terminalWidth), nil
	case "table":
		return newTableReporter(writer, false, terminalWidth), nil
	case "markdown":
		return newTableReporter(writer, true, terminalWidth), nil
	case "sarif":
		return newSarifReporter(writer), nil
	case "gh-annotations":
		return newGHAnnotationsReporter(writer), nil
	case "cyclonedx-1-4":
		return newCycloneDXReporter(writer, models.CycloneDXVersion14), nil
	case "cyclonedx-1-5":
		return newCycloneDXReporter(writer, models.CycloneDXVersion15), nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
