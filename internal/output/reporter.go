package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

type Reporter struct {
	stdout       io.Writer
	stderr       io.Writer
	outputAsJSON bool
}

func NewReporter(stdout io.Writer, stderr io.Writer, outputAsJSON bool) *Reporter {
	return &Reporter{
		stdout:       stdout,
		stderr:       stderr,
		outputAsJSON: outputAsJSON,
	}
}

// NewVoidReporter creates a reporter that doesn't report to anywhere
func NewVoidReporter() *Reporter {
	stdout := new(strings.Builder)
	stderr := new(strings.Builder)
	return NewReporter(stdout, stderr, false)
}

// PrintError writes the given message to stderr, regardless of if the reporter
// is outputting as JSON or not
func (r *Reporter) PrintError(msg string) {
	fmt.Fprint(r.stderr, msg)
}

// PrintText writes the given message to stdout, _unless_ the reporter is set
// to output as JSON, in which case it writes the message to stderr.
//
// This should be used for content that should always be outputted, but that
// should not be captured when piping if outputting JSON.
func (r *Reporter) PrintText(msg string) {
	target := r.stdout

	if r.outputAsJSON {
		target = r.stderr
	}

	fmt.Fprint(target, msg)
}

func (r *Reporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	if r.outputAsJSON {
		return PrintJSONResults(vulnResult, r.stdout)
	}

	PrintTableResults(vulnResult, r.stdout)

	return nil
}
