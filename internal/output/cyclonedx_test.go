package output_test

import (
	"bytes"
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
		if err != nil {
			t.Errorf("%v", err)
		}
		testutility.NewSnapshot().MatchText(t, outputWriter.String())
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testCycloneDXResults(t, tt.version, tt.testFn)
		})
	}
}
