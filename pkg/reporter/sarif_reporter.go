package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type SARIFReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func NewSarifReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *SARIFReporter {
	return &SARIFReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		hasErrored: false,
	}
}

func (r *SARIFReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(r.stderr, format, a...)
	r.hasErrored = true
}

func (r *SARIFReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *SARIFReporter) Warnf(format string, a ...any) {
	if r.CanPrintAtLevel(WarnLevel) {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *SARIFReporter) Infof(format string, a ...any) {
	if r.CanPrintAtLevel(InfoLevel) {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *SARIFReporter) Verbosef(format string, a ...any) {
	if r.CanPrintAtLevel(VerboseLevel) {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *SARIFReporter) CanPrintAtLevel(lvl VerbosityLevel) bool {
	return lvl <= r.level
}

func (r *SARIFReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintSARIFReport(vulnResult, r.stdout)
}
