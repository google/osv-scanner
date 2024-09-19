package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_groupFixedVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []models.VulnerabilityFlattened
		want testutility.Snapshot
	}{
		{
			name: "",
			args: testutility.LoadJSONFixture[[]models.VulnerabilityFlattened](t, "fixtures/flattened_vulns.json"),
			want: testutility.NewSnapshot(),
		},
		{
			name: "",
			args: testutility.LoadJSONFixtureWithWindowsReplacements[[]models.VulnerabilityFlattened](t,
				"fixtures/flattened_vulns.json",
				map[string]string{
					"/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock",
					"/path/to/scorecard-check-osv-e2e/go.mod":                      "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod",
				},
			),
			want: testutility.NewSnapshot().WithWindowsReplacements(
				map[string]string{
					"D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock": "/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock",
					"D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod":                         "/path/to/scorecard-check-osv-e2e/go.mod",
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := groupFixedVersions(tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}

func Test_mapIDsToGroupedSARIFFinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args models.VulnerabilityResults
		want testutility.Snapshot
	}{
		{
			args: testutility.LoadJSONFixtureWithWindowsReplacements[models.VulnerabilityResults](t,
				"fixtures/test-vuln-results-a.json",
				map[string]string{
					"/path/to/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock",
					"/path/to/go.mod":                      "D:\\\\path\\\\to\\\\go.mod",
				},
			),
			want: testutility.NewSnapshot().WithWindowsReplacements(
				map[string]string{
					"D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock": "/path/to/sub-rust-project/Cargo.lock",
					"D:\\\\path\\\\to\\\\go.mod":                         "/path/to/go.mod",
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := mapIDsToGroupedSARIFFinding(&tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}
