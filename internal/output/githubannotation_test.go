package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestPrintGHAnnotationReport_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGHAnnotationReport(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing GH annotation output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintGHAnnotationReport_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGHAnnotationReport(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing GH annotation output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintGHAnnotationReport_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGHAnnotationReport(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing GH annotation output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

// TestPrintGHAnnotationReport_CRSanitization verifies that carriage return characters
// in package paths and names are URL-encoded as %0D rather than emitted raw.
// Raw \r in GitHub Actions annotation output is treated as a line boundary by the
// runner, enabling workflow command injection (e.g. ::warning::, ::add-mask::).
func TestPrintGHAnnotationReport_CRSanitization(t *testing.T) {
	t.Parallel()

	// Construct a VulnerabilityResults with \r embedded in the source path,
	// simulating a crafted file path that could be used for command injection.
	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{
					Path: "legitimate-scan\r::warning::INJECTED/package-lock.json",
					Type: "lockfile",
				},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{
							Name:      "lodash",
							Version:   "4.17.20",
							Ecosystem: "npm",
						},
						Groups: []models.GroupInfo{
							{
								IDs:         []string{"GHSA-35jh-r3h4-6jhm"},
								MaxSeverity: "7.2",
							},
						},
					},
				},
			},
		},
	}

	outputWriter := &bytes.Buffer{}
	err := output.PrintGHAnnotationReport(vulnResult, outputWriter)
	if err != nil {
		t.Errorf("Error writing GH annotation output: %s", err)
	}

	result := outputWriter.String()

	// The output must not contain a raw carriage return — it must be encoded as %0D.
	if strings.Contains(result, "\r") {
		t.Errorf("GH annotation output contains raw \\r character, which enables workflow command injection.\nOutput: %q", result)
	}

	// The encoded form must be present instead.
	if !strings.Contains(result, "%0D") {
		t.Errorf("GH annotation output does not contain %%0D encoding for \\r character.\nOutput: %q", result)
	}
}
