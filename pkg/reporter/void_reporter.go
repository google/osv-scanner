package reporter

import (
	"github.com/google/osv-scanner/pkg/models"
)

type VoidReporter struct {
	hasErrored bool
}

func (r *VoidReporter) Errorf(_ string, _ ...any) {
	r.hasErrored = true
}

func (r *VoidReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *VoidReporter) Warnf(_ string, _ ...any) {
}

func (r *VoidReporter) Infof(_ string, _ ...any) {
}

func (r *VoidReporter) Verbosef(_ string, _ ...any) {
}

func (r *VoidReporter) PrintResult(_ *models.VulnerabilityResults) error {
	return nil
}
