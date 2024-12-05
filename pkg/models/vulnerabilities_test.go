package models_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func TestVulnerabilities_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		vs   models.Vulnerabilities
	}{
		{
			name: "nil",
			vs:   nil,
		},
		{
			name: "no vulnerabilities",
			vs:   models.Vulnerabilities{},
		},
		{
			name: "one vulnerability",
			vs:   models.Vulnerabilities{models.Vulnerability{ID: "GHSA-1"}},
		},
		{
			name: "multiple vulnerabilities",
			vs: models.Vulnerabilities{
				models.Vulnerability{ID: "GHSA-1"},
				models.Vulnerability{ID: "GHSA-2"},
				models.Vulnerability{ID: "GHSA-3"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testutility.NewSnapshot().MatchJSON(t, tt.vs)
		})
	}
}
