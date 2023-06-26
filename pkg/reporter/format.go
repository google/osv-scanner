package reporter

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

var format = []string{"table", "json", "markdown", "sarif"}

func Format() []string {
	return format
}

func GetReporter(format string, stdout, stderr io.Writer, fileOutput bool) (Reporter, error) {
	var width int
	if !fileOutput {
		var err error
		width, _, err = term.GetSize(int(os.Stdout.Fd()))
		if err != nil { // If output is not a terminal,
			width = 0
		}
	} else { // Output is a file
		width = 0
	}

	switch format {
	case "json":
		return NewJSONReporter(stdout, stderr), nil
	case "table":
		return NewTableReporter(stdout, stderr, false, width), nil
	case "markdown":
		return NewTableReporter(stdout, stderr, true, width), nil
	case "sarif":
		return NewSarifReporter(stdout, stderr), nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
