package cmdreporter

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
		return &htmlReporter{writer}, nil
	case "json":
		return &jsonReporter{writer}, nil
	case "vertical":
		return &verticalReporter{writer, terminalWidth}, nil
	case "table":
		return &tableReporter{writer, false, terminalWidth}, nil
	case "markdown":
		return &tableReporter{writer, true, terminalWidth}, nil
	case "sarif":
		return &sarifReporter{writer}, nil
	case "gh-annotations":
		return &ghAnnotationsReporter{writer}, nil
	case "cyclonedx-1-4":
		return &cycloneDXReporter{writer, models.CycloneDXVersion14}, nil
	case "cyclonedx-1-5":
		return &cycloneDXReporter{writer, models.CycloneDXVersion15}, nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
