package reporter

import (
	"github.com/google/osv-scanner/pkg/models"
)

type Reporter interface {
	// PrintError writes the given message to stderr, regardless of if the reporter
	// is outputting as JSON or not
	PrintError(msg string)
	// PrintErrorf prints errors in an appropriate manner to ensure that results
	// are printed in a way that is semantically valid for the intended consumer,
	// and tracking that an error has been printed.
	//
	// Where the error is actually printed (if at all) is entirely up to the actual
	// reporter, though generally it will be to stderr.
	PrintErrorf(msg string, a ...any)
	HasPrintedError() bool
	// PrintText writes the given message to stdout, _unless_ the reporter is set
	// to output as JSON, in which case it writes the message to stderr.
	//
	// This should be used for content that should always be outputted, but that
	// should not be captured when piping if outputting JSON.
	PrintText(msg string)
	// PrintTextf prints text in an appropriate manner to ensure that results
	// are printed in a way that is semantically valid for the intended consumer.
	//
	// Where the text is actually printed (if at all) is entirely up to the actual
	// reporter; in most cases for "human format" reporters this will be stdout
	// whereas for "machine format" reporters this will stderr.
	PrintTextf(msg string, a ...any)
	PrintResult(vulnResult *models.VulnerabilityResults) error
}
