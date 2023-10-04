package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func TestGroupFixedVersions(t *testing.T) {
	t.Parallel()

	type args struct {
		flattened []models.VulnerabilityFlattened
	}
	tests := []struct {
		name     string
		args     args
		wantPath string
	}{
		{
			name: "",
			args: args{
				flattened: testutility.LoadJSONFixture[[]models.VulnerabilityFlattened](t, "fixtures/flattened_vulns.json"),
			},
			wantPath: "fixtures/group_fixed_version_output.json",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := output.GroupFixedVersions(tt.args.flattened)
			testutility.AssertMatchFixtureJSON(t, tt.wantPath, got)
		})
	}
}

func TestPrintSARIFReport(t *testing.T) {
	t.Parallel()

	type args struct {
		vulnRes models.VulnerabilityResults
	}
	tests := []struct {
		name     string
		args     args
		wantPath string
	}{
		{
			name: "",
			args: args{
				vulnRes: testutility.LoadJSONFixture[models.VulnerabilityResults](t, "fixtures/test-vuln-results-a.json"),
			},
			wantPath: "fixtures/test-vuln-results-a.sarif",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bufOut := bytes.Buffer{}
			err := output.PrintSARIFReport(&tt.args.vulnRes, &bufOut)
			if err != nil {
				t.Errorf("Error writing SARIF output: %s", err)
			}
			testutility.CreateTextFixture(t, tt.wantPath, bufOut.String())
		})
	}
}
