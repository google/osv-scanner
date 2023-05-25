package reporter

import (
	"fmt"
	"io"
)

var format = []string{"table", "json", "markdown", "report"}

func Format() []string {
	return format
}

func GetReporter(format string, stdout, stderr io.Writer) (Reporter, error) {
	switch format {
	case "json":
		return NewJSONReporter(stdout, stderr), nil
	case "table":
		return NewTableReporter(stdout, stderr, false), nil
	case "markdown":
		return NewTableReporter(stdout, stderr, true), nil
	case "report":
		return NewMarkdownReporter(stdout, stderr), nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
