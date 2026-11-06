package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func testCycloneDXResults(t *testing.T, version models.CycloneDXVersion, testFunc func(*testing.T, func(*testing.T, outputTestCaseArgs))) {
	t.Helper()
	testFunc(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()
		outputWriter := &bytes.Buffer{}
		err := output.PrintCycloneDXResults(args.vulnResult, version, outputWriter)
		testutility.NewSnapshot().MatchText(t, outputWriter.String())

		// some packages cannot currently be represented (such as those from OS
		// ecosystems which we cannot determine a PURL for), which is reported as an
		// error after the rest of the output has been written
		if err != nil {
			testutility.NewSnapshot().MatchText(t, err.Error())
		}
	})
}

func TestPrintCycloneDXResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		version models.CycloneDXVersion
		testFn  func(*testing.T, func(*testing.T, outputTestCaseArgs))
	}{
		{"CycloneDX14_WithVulnerabilities", models.CycloneDXVersion14, testOutputWithVulnerabilities},
		{"CycloneDX14_WithLicenseViolations", models.CycloneDXVersion14, testOutputWithLicenseViolations},
		{"CycloneDX14_WithMixedIssues", models.CycloneDXVersion14, testOutputWithMixedIssues},
		{"CycloneDX15_WithVulnerabilities", models.CycloneDXVersion15, testOutputWithVulnerabilities},
		{"CycloneDX15_WithLicenseViolations", models.CycloneDXVersion15, testOutputWithLicenseViolations},
		{"CycloneDX15_WithMixedIssues", models.CycloneDXVersion15, testOutputWithMixedIssues},
		{"CycloneDX16_WithVulnerabilities", models.CycloneDXVersion16, testOutputWithVulnerabilities},
		{"CycloneDX16_WithLicenseViolations", models.CycloneDXVersion16, testOutputWithLicenseViolations},
		{"CycloneDX16_WithMixedIssues", models.CycloneDXVersion16, testOutputWithMixedIssues},
		{"CycloneDX17_WithVulnerabilities", models.CycloneDXVersion17, testOutputWithVulnerabilities},
		{"CycloneDX17_WithLicenseViolations", models.CycloneDXVersion17, testOutputWithLicenseViolations},
		{"CycloneDX17_WithMixedIssues", models.CycloneDXVersion17, testOutputWithMixedIssues},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testCycloneDXResults(t, tt.version, tt.testFn)
		})
	}
}

func TestPrintCycloneDXResults_LicensesFormatting(t *testing.T) {
	t.Parallel()

	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: "/test/package-lock.json", Type: "lockfile"},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{
							Name:      "pako",
							Version:   "1.0.11",
							Ecosystem: "npm",
						},
						Licenses: []models.License{"MIT AND Zlib"},
					},
					{
						Package: models.PackageInfo{
							Name:      "custom-pkg",
							Version:   "1.0.0",
							Ecosystem: "npm",
						},
						Licenses: []models.License{"non-standard"},
					},
					{
						Package: models.PackageInfo{
							Name:      "standard-pkg",
							Version:   "2.0.0",
							Ecosystem: "npm",
						},
						Licenses: []models.License{"MIT"},
					},
				},
			},
		},
	}

	buf := &bytes.Buffer{}
	err := output.PrintCycloneDXResults(vulnResult, models.CycloneDXVersion15, buf)
	if err != nil {
		t.Fatalf("PrintCycloneDXResults error: %v", err)
	}

	outStr := buf.String()
	if !strings.Contains(outStr, `"expression": "MIT AND Zlib"`) {
		t.Errorf("expected output to contain expression 'MIT AND Zlib', got:\n%s", outStr)
	}
	if !strings.Contains(outStr, `"name": "non-standard"`) {
		t.Errorf("expected output to contain license name 'non-standard', got:\n%s", outStr)
	}
	if !strings.Contains(outStr, `"id": "MIT"`) {
		t.Errorf("expected output to contain license id 'MIT', got:\n%s", outStr)
	}
}
