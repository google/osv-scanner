package output

import (
	"testing"

	"github.com/google/osv-scanner/internal/testfixture"
	"github.com/google/osv-scanner/internal/testsnapshot"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_groupFixedVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []models.VulnerabilityFlattened
		want testsnapshot.Snapshot
	}{
		{
			name: "",
			args: testfixture.LoadJSON[[]models.VulnerabilityFlattened](t,
				testfixture.New(
					"fixtures/flattened_vulns.json",
					map[string]string{},
				),
			),
			want: testsnapshot.New(

				map[string]string{},
			),
		},
		{
			name: "",
			args: testfixture.LoadJSON[[]models.VulnerabilityFlattened](t,
				testfixture.New(
					"fixtures/flattened_vulns.json",
					map[string]string{
						"/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock",
						"/path/to/scorecard-check-osv-e2e/go.mod":                      "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod",
					},
				),
			),
			want: testsnapshot.New(map[string]string{
				"/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock",
				"/path/to/scorecard-check-osv-e2e/go.mod":                      "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod",
			}),
		},
	}
	for _, tt := range tests {
		tt := tt
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
		want testsnapshot.Snapshot
	}{
		{
			args: testfixture.LoadJSON[models.VulnerabilityResults](t,
				testfixture.New(
					"fixtures/test-vuln-results-a.json",
					map[string]string{
						"/path/to/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock",
						"/path/to/go.mod":                      "D:\\\\path\\\\to\\\\go.mod",
					},
				),
			),
			want: testsnapshot.New(map[string]string{
				"/path/to/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock",
				"/path/to/go.mod":                      "D:\\\\path\\\\to\\\\go.mod",
			}),
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := mapIDsToGroupedSARIFFinding(&tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}
