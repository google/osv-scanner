package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/testsnapshot"
	"github.com/google/osv-scanner/pkg/models"
)

func TestGroupFixedVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []models.VulnerabilityFlattened
		want testsnapshot.Snapshot
	}{
		{
			name: "",
			args: testsnapshot.LoadJSON[[]models.VulnerabilityFlattened](t,
				testsnapshot.New(
					"fixtures/flattened_vulns.json",
					map[string]string{},
				),
			),
			want: testsnapshot.New(
				"fixtures/group_fixed_version_output.json",
				map[string]string{},
			),
		},
		{
			name: "",
			args: testsnapshot.LoadJSON[[]models.VulnerabilityFlattened](t,
				testsnapshot.New(
					"fixtures/flattened_vulns.json",
					map[string]string{
						"/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock",
						"/path/to/scorecard-check-osv-e2e/go.mod":                      "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod",
					},
				),
			),
			want: testsnapshot.New(
				"fixtures/group_fixed_version_output.json",
				map[string]string{
					"/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock",
					"/path/to/scorecard-check-osv-e2e/go.mod":                      "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod",
				},
			),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := output.GroupFixedVersions(tt.args)
			testsnapshot.AssertJSON(t, tt.want, got)
		})
	}
}

func TestPrintSARIFReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args models.VulnerabilityResults
		want testsnapshot.Snapshot
	}{
		{
			name: "",
			args: testsnapshot.LoadJSON[models.VulnerabilityResults](t,
				testsnapshot.New(
					"fixtures/test-vuln-results-a.json",
					map[string]string{
						"/path/to/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock",
						"/path/to/go.mod":                      "D:\\\\path\\\\to\\\\go.mod",
					},
				),
			),
			want: testsnapshot.New(
				"fixtures/test-vuln-results-a.sarif",
				map[string]string{
					"lockfile:/path/to/sub-rust-project/Cargo.lock": "lockfile:D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock",
					"lockfile:/path/to/go.mod":                      "lockfile:D:\\\\path\\\\to\\\\go.mod",
					"/path/to/sub-rust-project/osv-scanner.toml":    "D:\\\\path\\\\to\\\\sub-rust-project/osv-scanner.toml",
					"/path/to/osv-scanner.toml":                     "D:\\\\path\\\\to/osv-scanner.toml",
					"file:///path/to":                               "file:///D:/path/to",
				},
			),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bufOut := bytes.Buffer{}
			err := output.PrintSARIFReport(&tt.args, &bufOut)
			if err != nil {
				t.Errorf("Error writing SARIF output: %s", err)
			}
			testsnapshot.AssertText(t, tt.want, bufOut.String())
		})
	}
}
