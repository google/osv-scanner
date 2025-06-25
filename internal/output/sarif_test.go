package output_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestGroupFixedVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []models.VulnerabilityFlattened
		want testutility.Snapshot
	}{
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
			got := output.GroupFixedVersions(tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}

func TestPrintSARIFReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args models.VulnerabilityResults
		want testutility.Snapshot
	}{
		{
			name: "",
			args: testutility.LoadJSONFixtureWithWindowsReplacements[models.VulnerabilityResults](t,
				"fixtures/test-vuln-results-a.json",
				map[string]string{
					"/path/to/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock",
					"/path/to/go.mod":                      "D:\\\\path\\\\to\\\\go.mod",
				},
			),
			want: testutility.NewSnapshot().WithWindowsReplacements(
				map[string]string{
					"lockfile:D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock": "lockfile:/path/to/sub-rust-project/Cargo.lock",
					"lockfile:D:\\\\path\\\\to\\\\go.mod":                         "lockfile:/path/to/go.mod",
					"D:\\\\path\\\\to\\\\sub-rust-project\\\\osv-scanner.toml":    "/path/to/sub-rust-project/osv-scanner.toml",
					"D:\\\\path\\\\to\\\\osv-scanner.toml":                        "/path/to/osv-scanner.toml",
					"file:///D:/path/to":                                          "file:///path/to",
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			jsonStructure := buildJSONSarifReport(t, &tt.args)

			tt.want.MatchJSON(t, jsonStructure)
		})
	}
}

func TestPrintSARIFReport_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		jsonStructure := buildJSONSarifReport(t, args.vulnResult)

		testutility.NewSnapshot().WithWindowsReplacements(
			map[string]string{
				"path\\\\to\\\\my\\\\first\\\\osv-scanner.toml":  "path/to/my/first/osv-scanner.toml",
				"path\\\\to\\\\my\\\\second\\\\osv-scanner.toml": "path/to/my/second/osv-scanner.toml",
				"path\\\\to\\\\my\\\\third\\\\osv-scanner.toml":  "path/to/my/third/osv-scanner.toml",
			}).MatchJSON(t, jsonStructure)
	})
}

func TestPrintSARIFReport_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		jsonStructure := buildJSONSarifReport(t, args.vulnResult)

		testutility.NewSnapshot().WithWindowsReplacements(
			map[string]string{
				"path\\\\to\\\\my\\\\first\\\\osv-scanner.toml":  "path/to/my/first/osv-scanner.toml",
				"path\\\\to\\\\my\\\\second\\\\osv-scanner.toml": "path/to/my/second/osv-scanner.toml",
				"path\\\\to\\\\my\\\\third\\\\osv-scanner.toml":  "path/to/my/third/osv-scanner.toml",
			}).MatchJSON(t, jsonStructure)
	})
}

func TestPrintSARIFReport_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		jsonStructure := buildJSONSarifReport(t, args.vulnResult)

		testutility.NewSnapshot().WithWindowsReplacements(
			map[string]string{
				"path\\\\to\\\\my\\\\first\\\\osv-scanner.toml":  "path/to/my/first/osv-scanner.toml",
				"path\\\\to\\\\my\\\\second\\\\osv-scanner.toml": "path/to/my/second/osv-scanner.toml",
				"path\\\\to\\\\my\\\\third\\\\osv-scanner.toml":  "path/to/my/third/osv-scanner.toml",
			}).MatchJSON(t, jsonStructure)
	})
}

func buildJSONSarifReport(t *testing.T, res *models.VulnerabilityResults) map[string]any {
	t.Helper()

	outputWriter := &bytes.Buffer{}
	err := output.PrintSARIFReport(res, outputWriter)

	if err != nil {
		t.Errorf("Error writing SARIF output: %s", err)
	}

	jsonStructure := map[string]any{}
	err = json.NewDecoder(outputWriter).Decode(&jsonStructure)
	if err != nil {
		t.Errorf("Error decoding SARIF output: %s", err)
	}

	return jsonStructure
}
