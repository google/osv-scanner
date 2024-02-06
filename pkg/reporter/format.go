package reporter

import (
	"fmt"
	"io"
)

var format = []string{"table", "json", "markdown", "sarif", "gh-annotations", "cyclonedx-1-4"}

func Format() []string {
	return format
}

// New returns an implementation of the reporter interface depending on the format passed in
// set terminalWidth as 0 to indicate the output is not a terminal
func New(format string, stdout, stderr io.Writer, terminalWidth int) (Reporter, error) {
	switch format {
	case "json":
		return NewJSONReporter(stdout, stderr), nil
	case "table":
		return NewTableReporter(stdout, stderr, false, terminalWidth), nil
	case "markdown":
		return NewTableReporter(stdout, stderr, true, terminalWidth), nil
	case "sarif":
		return NewSarifReporter(stdout, stderr), nil
	case "gh-annotations":
		return NewGHAnnotationsReporter(stdout, stderr), nil
	case "cyclonedx-1-4":
		return NewCycloneDXReporter(stdout, stderr), nil

	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
