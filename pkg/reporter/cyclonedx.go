package reporter

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/google/osv-scanner/v2/internal/output"

	"github.com/google/osv-scanner/v2/pkg/models"
)

type CycloneDXReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	version    models.CycloneDXVersion
	level      VerbosityLevel
}

func NewCycloneDXReporter(stdout, stderr io.Writer, version models.CycloneDXVersion, level VerbosityLevel) *CycloneDXReporter {
	return &CycloneDXReporter{
		stdout:     stdout,
		stderr:     stderr,
		hasErrored: false,
		version:    version,
		level:      level,
	}
}

func (r *CycloneDXReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(r.stderr, format, a...)
	r.hasErrored = true
}

func (r *CycloneDXReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *CycloneDXReporter) Warnf(format string, a ...any) {
	if WarnLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *CycloneDXReporter) Infof(format string, a ...any) {
	if InfoLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *CycloneDXReporter) PrintResult(vulnerabilityResults *models.VulnerabilityResults) error {
	errs := output.PrintCycloneDXResults(vulnerabilityResults, r.version, r.stdout)
	if errs != nil {
		for _, err := range strings.Split(errs.Error(), "\n") {
			slog.Warn(fmt.Sprintf("Failed to parse package URL: %v", err))
		}
	}

	return nil
}
