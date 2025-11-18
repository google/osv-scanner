package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

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
				"testdata/test-vuln-results-a.json",
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

	cwd := testutility.GetCurrentWorkingDirectory(t)

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		jsonStructure := buildJSONSarifReport(t, args.vulnResult)

		testutility.NewSnapshot().WithWindowsReplacements(
			map[string]string{
				strings.ReplaceAll(cwd, "\\", "\\\\"): strings.ReplaceAll(cwd, "\\", "/"),

				"\\\\path\\\\to\\\\my\\\\first\\\\osv-scanner.toml":  "/path/to/my/first/osv-scanner.toml",
				"\\\\path\\\\to\\\\my\\\\second\\\\osv-scanner.toml": "/path/to/my/second/osv-scanner.toml",
				"\\\\path\\\\to\\\\my\\\\third\\\\osv-scanner.toml":  "/path/to/my/third/osv-scanner.toml",
			}).MatchJSON(t, jsonStructure)
	})
}

func TestPrintSARIFReport_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	cwd := testutility.GetCurrentWorkingDirectory(t)

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		jsonStructure := buildJSONSarifReport(t, args.vulnResult)

		testutility.NewSnapshot().WithWindowsReplacements(
			map[string]string{
				strings.ReplaceAll(cwd, "\\", "\\\\"): strings.ReplaceAll(cwd, "\\", "/"),

				"\\\\path\\\\to\\\\my\\\\first\\\\osv-scanner.toml":  "/path/to/my/first/osv-scanner.toml",
				"\\\\path\\\\to\\\\my\\\\second\\\\osv-scanner.toml": "/path/to/my/second/osv-scanner.toml",
				"\\\\path\\\\to\\\\my\\\\third\\\\osv-scanner.toml":  "/path/to/my/third/osv-scanner.toml",
			}).MatchJSON(t, jsonStructure)
	})
}

func TestPrintSARIFReport_WithMixedIssues(t *testing.T) {
	t.Parallel()

	cwd := testutility.GetCurrentWorkingDirectory(t)

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		jsonStructure := buildJSONSarifReport(t, args.vulnResult)

		testutility.NewSnapshot().WithWindowsReplacements(
			map[string]string{
				strings.ReplaceAll(cwd, "\\", "\\\\"): strings.ReplaceAll(cwd, "\\", "/"),

				"\\\\path\\\\to\\\\my\\\\first\\\\osv-scanner.toml":  "/path/to/my/first/osv-scanner.toml",
				"\\\\path\\\\to\\\\my\\\\second\\\\osv-scanner.toml": "/path/to/my/second/osv-scanner.toml",
				"\\\\path\\\\to\\\\my\\\\third\\\\osv-scanner.toml":  "/path/to/my/third/osv-scanner.toml",
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

	replacedJSON := testutility.ReplaceJSONInput(
		t,
		outputWriter.String(),
		testutility.ReplacePartialFingerprintHash.Path,
		testutility.ReplacePartialFingerprintHash.ReplaceFunc,
	)

	jsonStructure := map[string]any{}
	err = json.NewDecoder(bytes.NewBufferString(replacedJSON)).Decode(&jsonStructure)
	if err != nil {
		t.Errorf("Error decoding SARIF output: %s", err)
	}

	return jsonStructure
}
