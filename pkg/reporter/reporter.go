package reporter

import (
	"github.com/google/osv-scanner/pkg/models"
)

// Reporter provides printing operations for vulnerability results and for runtime information (depending on the verbosity
// level given to the Reporter implementation).
//
// When printing non-error-related runtime information, it is entirely up to the Reporter implementation as to where
// the text is actually printed (if at all); in most cases for "human format" reporters this will be stdout whereas
// for "machine format" reporters this will be stderr.
type Reporter interface {
	// Errorf prints errors in an appropriate manner to ensure that results
	// are printed in a way that is semantically valid for the intended consumer,
	// and tracking that an error has been printed.
	//
	// Where the error is actually printed (if at all) is entirely up to the actual
	// reporter, though generally it will be to stderr.
	Errorf(format string, a ...any)
	// HasErrored returns true if there have been any calls to Errorf.
	//
	// This does not actually represent if the error was actually printed anywhere
	// since what happens to the error message is up to the actual reporter.
	HasErrored() bool
	// Warnf prints text indicating potential issues or something that should be brought to the attention of users.
	Warnf(format string, a ...any)
	// Infof prints text providing general information about what OSV-Scanner is doing during its runtime.
	Infof(format string, a ...any)
	// Verbosef prints text providing additional information about the inner workings of OSV-Scanner to the user.
	Verbosef(format string, a ...any)
	// PrintResult prints the models.VulnerabilityResults per the logic of the
	// actual reporter
	PrintResult(vulnResult *models.VulnerabilityResults) error
}
