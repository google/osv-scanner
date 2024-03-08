package reporter

import (
	"github.com/google/osv-scanner/pkg/models"
)

type VoidReporter struct {
	hasPrintedError bool
}

func (r *VoidReporter) PrintError(msg string) {
	r.PrintErrorf(msg)
}

func (r *VoidReporter) PrintErrorf(msg string, a ...any) {
	r.hasPrintedError = true
}

func (r *VoidReporter) PrintWarnf(msg string, a ...any) {}

func (r *VoidReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *VoidReporter) PrintText(msg string) {
	r.PrintTextf(msg)
}

func (r *VoidReporter) PrintTextf(msg string, a ...any) {
}

func (r *VoidReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return nil
}
