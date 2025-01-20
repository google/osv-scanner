package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/pkg/models"
)

var format = []string{"table", "vertical", "json", "markdown", "sarif", "gh-annotations", "cyclonedx-1-4", "cyclonedx-1-5"}

func Format() []string {
	return format
}

// New returns an implementation of the reporter interface depending on the format passed in
// set terminalWidth as 0 to indicate the output is not a terminal
func New(format string, stdout, stderr io.Writer, level VerbosityLevel, terminalWidth int) (Reporter, error) {
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
