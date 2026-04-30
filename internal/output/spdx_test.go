package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/text"
)

func normalizeSPDXOutput(t *testing.T, str string) string {
	t.Helper()

	str = text.StripEscape(str)
	str = cachedregexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`).ReplaceAllString(str, `<uuid>`)
	str = cachedregexp.MustCompile(`"created": ".+T.+Z"`).ReplaceAllString(str, `"created": "<timestamp>"`)

	return str
}

func TestPrintSPDXResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintSPDXResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, normalizeSPDXOutput(t, outputWriter.String()))
	})
}

func TestPrintSPDXResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintSPDXResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, normalizeSPDXOutput(t, outputWriter.String()))
	})
}

func TestPrintSPDXResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintSPDXResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, normalizeSPDXOutput(t, outputWriter.String()))
	})
}

// TestPrintSPDXResults_WithOSVScannerJSONSource tests that packages loaded from an
// osv-scanner.json results file (which have Inventory == nil) are correctly included
// in the SPDX output with the right PURL types. This is a regression test for issue #2192.
func TestPrintSPDXResults_WithOSVScannerJSONSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		vulnResult *models.VulnerabilityResults
	}{
		{
			name: "npm_package_from_osv_scanner_json",
			vulnResult: &models.VulnerabilityResults{
				Results: []models.PackageSource{
					{
						Source: models.SourceInfo{Path: "/path/to/osv-scanner.json", Type: models.SourceTypeProjectPackage},
						Packages: []models.PackageVulns{
							{
								// Inventory is nil, as it would be when loaded from osv-scanner.json
								Package: models.PackageInfo{
									Name:      "lodash",
									Version:   "4.17.11",
									Ecosystem: "npm",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_ecosystems_from_osv_scanner_json",
			vulnResult: &models.VulnerabilityResults{
				Results: []models.PackageSource{
					{
						Source: models.SourceInfo{Path: "/path/to/osv-scanner.json", Type: models.SourceTypeProjectPackage},
						Packages: []models.PackageVulns{
							{
								Package: models.PackageInfo{
									Name:      "requests",
									Version:   "2.25.1",
									Ecosystem: "PyPI",
								},
							},
							{
								Package: models.PackageInfo{
									Name:      "com.example:mylib",
									Version:   "1.0.0",
									Ecosystem: "Maven",
								},
							},
							{
								Package: models.PackageInfo{
									Name:      "github.com/foo/bar",
									Version:   "v1.2.3",
									Ecosystem: "Go",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			outputWriter := &bytes.Buffer{}
			err := output.PrintSPDXResults(tt.vulnResult, outputWriter)

			if err != nil {
				t.Errorf("%v", err)
			}

			testutility.NewSnapshot().MatchText(t, normalizeSPDXOutput(t, outputWriter.String()))
		})
	}
}
