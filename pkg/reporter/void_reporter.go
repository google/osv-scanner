package reporter

import (
	"github.com/google/osv-scanner/v2/pkg/models"
)

type voidReporter struct {
	hasErrored bool
}

func (r *voidReporter) Errorf(_ string, _ ...any) {
	r.hasErrored = true
}

func (r *voidReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *voidReporter) Warnf(_ string, _ ...any) {
}

func (r *voidReporter) Infof(_ string, _ ...any) {
}

func (r *voidReporter) PrintResult(_ *models.VulnerabilityResults) error {
	return nil
}
