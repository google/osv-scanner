package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

type Reporter struct {
	stdout          io.Writer
	stderr          io.Writer
	format          string
	hasPrintedError bool
}

func NewReporter(stdout io.Writer, stderr io.Writer, format string) *Reporter {
	return &Reporter{
		stdout: stdout,
		stderr: stderr,
		format: format,
	}
}

// NewVoidReporter creates a reporter that doesn't report to anywhere
func NewVoidReporter() *Reporter {
	stdout := new(strings.Builder)
	stderr := new(strings.Builder)

	return NewReporter(stdout, stderr, "")
}

// PrintError writes the given message to stderr, regardless of if the reporter
// is outputting as JSON or not
func (r *Reporter) PrintError(msg string) {
	fmt.Fprint(r.stderr, msg)
	r.hasPrintedError = true
}

func (r *Reporter) HasPrintedError() bool {
	return r.hasPrintedError
}

// PrintText writes the given message to stdout, _unless_ the reporter is set
// to output as JSON, in which case it writes the message to stderr.
//
// This should be used for content that should always be outputted, but that
// should not be captured when piping if outputting JSON.
func (r *Reporter) PrintText(msg string) {
	target := r.stdout

	if r.format == "json" {
		target = r.stderr
	}

	fmt.Fprint(target, msg)
}

func (r *Reporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	switch r.format {
	case "json":
		return PrintJSONResults(vulnResult, r.stdout)
	case "markdown":
		PrintMarkdownTableResults(vulnResult, r.stdout)
	case "table":
		PrintTableResults(vulnResult, r.stdout)
	}

	return nil
}
