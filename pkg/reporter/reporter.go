package reporter

import (
	"github.com/google/osv-scanner/pkg/models"
)

type Reporter interface {
	// PrintError prints errors in an appropriate manner to ensure that results
	// are printed in a way that is semantically valid for the intended consumer,
	// and tracking that an error has been printed.
	//
	// Where the error is actually printed (if at all) is entirely up to the actual
	// reporter, though generally it will be to stderr.
	//
	// Deprecated: use PrintErrorf instead
	PrintError(msg string)
	// PrintErrorf prints errors in an appropriate manner to ensure that results
	// are printed in a way that is semantically valid for the intended consumer,
	// and tracking that an error has been printed.
	//
	// Where the error is actually printed (if at all) is entirely up to the actual
	// reporter, though generally it will be to stderr.
	PrintErrorf(msg string, a ...any)
	// PrintWarnf does the same thing than PrintErrorf but does not consider it as an error
	// The direct result of it is the result code which will still be a success if the error outputs only have
	// warnings.
	PrintWarnf(msg string, a ...any)
	// HasPrintedError returns true if there have been any calls to PrintError or
	// PrintErrorf.
	//
	// This does not actually represent if the error was actually printed anywhere
	// since what happens to the error message is up to the actual reporter.
	HasPrintedError() bool
	// PrintText prints text in an appropriate manner to ensure that results
	// are printed in a way that is semantically valid for the intended consumer.
	//
	// Where the text is actually printed (if at all) is entirely up to the actual
	// reporter; in most cases for "human format" reporters this will be stdout
	// whereas for "machine format" reporters this will stderr.
	//
	// Deprecated: use PrintTextf instead
	PrintText(msg string)
	// PrintTextf prints text in an appropriate manner to ensure that results
	// are printed in a way that is semantically valid for the intended consumer.
	//
	// Where the text is actually printed (if at all) is entirely up to the actual
	// reporter; in most cases for "human format" reporters this will be stdout
	// whereas for "machine format" reporters this will stderr.
	PrintTextf(msg string, a ...any)
	// PrintResult prints the models.VulnerabilityResults per the logic of the
	// actual reporter
	PrintResult(vulnResult *models.VulnerabilityResults) error
}
