package reporter

import (
	"github.com/google/osv-scanner/pkg/models"
)

type VoidReporter struct {
	hasErrored bool
}

func (r *VoidReporter) Errorf(msg string, a ...any) {
	r.hasErrored = true
}

func (r *VoidReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *VoidReporter) Warnf(msg string, a ...any) {
}

func (r *VoidReporter) Infof(msg string, a ...any) {
}

func (r *VoidReporter) Verbosef(msg string, a ...any) {
}

func (r *VoidReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return nil
}
