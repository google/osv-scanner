package reporter

import (
	"github.com/google/osv-scanner/pkg/models"
)

type Reporter interface {
	// PrintError writes the given message to stderr, regardless of if the reporter
	// is outputting as JSON or not
	PrintError(msg string)
	HasPrintedError() bool
	// PrintText writes the given message to stdout, _unless_ the reporter is set
	// to output as JSON, in which case it writes the message to stderr.
	//
	// This should be used for content that should always be outputted, but that
	// should not be captured when piping if outputting JSON.
	PrintText(msg string)
	PrintResult(vulnResult *models.VulnerabilityResults) error
}
