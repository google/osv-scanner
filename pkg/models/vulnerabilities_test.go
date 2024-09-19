package models_test

import (
	"encoding/json"
	"testing"

	"github.com/google/osv-scanner/pkg/models"
)

func TestVulnerabilities_MarshalJSON(t *testing.T) {
	t.Parallel()

	osv := models.Vulnerability{ID: "GHSA-1"}
	asJSON, err := json.Marshal(osv)

	if err != nil {
		t.Fatalf("Unable to marshal osv to JSON: %v", err)
	}

	tests := []struct {
		name string
		vs   models.Vulnerabilities
		want string
	}{
		{
			name: "",
			vs:   nil,
			want: "[]",
		},
		{
			name: "",
			vs:   models.Vulnerabilities(nil),
			want: "[]",
		},
		{
			name: "",
			vs:   models.Vulnerabilities{osv},
			want: "[" + string(asJSON) + "]",
		},
		{
			name: "",
			vs:   models.Vulnerabilities{osv, osv},
			want: "[" + string(asJSON) + "," + string(asJSON) + "]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.vs.MarshalJSON()
			if err != nil {
				t.Errorf("MarshalJSON() error = %v", err)

				return
			}

			if gotStr := string(got); gotStr != tt.want {
				t.Errorf("MarshalJSON() got = %v, want %v", gotStr, tt.want)
			}
		})
	}
}
