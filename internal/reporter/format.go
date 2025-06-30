package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/pkg/models"
)

var format = []string{"table", "html", "vertical", "json", "markdown", "sarif", "gh-annotations", "cyclonedx-1-4", "cyclonedx-1-5", "spdx-2-3"}

func Format() []string {
	return format
}

func newResultPrinter(format string, writer io.Writer, terminalWidth int, showAllVulns bool) (resultPrinter, error) {
	switch format {
	case "html":
		return &htmlReporter{writer}, nil
	case "json":
		return &jsonReporter{writer}, nil
	case "vertical":
		return &verticalReporter{writer, terminalWidth, showAllVulns}, nil
	case "table":
		return &tableReporter{writer, false, terminalWidth, showAllVulns}, nil
	case "markdown":
		return &tableReporter{writer, true, terminalWidth, showAllVulns}, nil
	case "sarif":
		return &sarifReporter{writer}, nil
	case "gh-annotations":
		return &ghAnnotationsReporter{writer}, nil
	case "cyclonedx-1-4":
		return &cycloneDXReporter{writer, models.CycloneDXVersion14}, nil
	case "cyclonedx-1-5":
		return &cycloneDXReporter{writer, models.CycloneDXVersion15}, nil
	case "cyclonedx-1-6":
		return &cycloneDXReporter{writer, models.CycloneDXVersion16}, nil
	case "spdx-2-3":
		return &spdxReporter{writer}, nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
