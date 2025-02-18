package models_test

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestVulnerabilities_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		vs   []osvschema.Vulnerability
	}{
		{
			name: "nil",
			vs:   nil,
		},
		{
			name: "no vulnerabilities",
			vs:   []osvschema.Vulnerability{},
		},
		{
			name: "one vulnerability",
			vs:   []osvschema.Vulnerability{osvschema.Vulnerability{ID: "GHSA-1"}},
		},
		{
			name: "multiple vulnerabilities",
			vs: []osvschema.Vulnerability{
				osvschema.Vulnerability{ID: "GHSA-1"},
				osvschema.Vulnerability{ID: "GHSA-2"},
				osvschema.Vulnerability{ID: "GHSA-3"},
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
