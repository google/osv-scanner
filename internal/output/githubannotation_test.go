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

// TestPrintGHAnnotationReport_PercentSanitization verifies that literal percent
// signs in the file path and message body are percent-encoded as %25 so that an
// attacker cannot inject pre-encoded sequences such as %0A or %0D.
func TestPrintGHAnnotationReport_PercentSanitization(t *testing.T) {
	t.Parallel()

	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{
					Path: "project%0A::warning::INJECTED/package-lock.json",
					Type: "lockfile",
				},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{
							Name:      "bad%0D::error::INJECTED",
							Version:   "1.0.0",
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

	if !strings.Contains(result, "%250A") {
		t.Errorf("GH annotation output does not contain %%250A encoding for pre-encoded newline.\nOutput: %q", result)
	}
	if !strings.Contains(result, "%250D") {
		t.Errorf("GH annotation output does not contain %%250D encoding for pre-encoded carriage return.\nOutput: %q", result)
	}
	if strings.Contains(result, "%0A::warning::") || strings.Contains(result, "%0D::error::") {
		t.Errorf("GH annotation output contains unescaped pre-encoded workflow command injection.\nOutput: %q", result)
	}
}

// TestPrintGHAnnotationReport_PropertyDelimiterSanitization verifies that colon
// and comma characters in the file= property are percent-encoded so they cannot
// be used to inject additional properties or terminate the current one.
func TestPrintGHAnnotationReport_PropertyDelimiterSanitization(t *testing.T) {
	t.Parallel()

	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{
					Path: "project,title=FAKE::warning::pwned/package:lock.json",
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

	if strings.Contains(result, "file=project,") || strings.Contains(result, "file=project,title=FAKE") {
		t.Errorf("GH annotation output contains unescaped comma in file= property, enabling property injection.\nOutput: %q", result)
	}
	if strings.Contains(result, "file=project%3A") || strings.Contains(result, "::warning::pwned") {
		t.Errorf("GH annotation output contains unescaped colon in file= property, enabling property injection.\nOutput: %q", result)
	}
	if !strings.Contains(result, "%2C") {
		t.Errorf("GH annotation output does not contain %%2C encoding for comma.\nOutput: %q", result)
	}
	if !strings.Contains(result, "%3A") {
		t.Errorf("GH annotation output does not contain %%3A encoding for colon.\nOutput: %q", result)
	}
}

// TestPrintGHAnnotationReport_NewlineInMessageSanitization verifies that newlines
// in the rendered table message body are encoded as %0A so they cannot break out
// of the workflow command line.
func TestPrintGHAnnotationReport_NewlineInMessageSanitization(t *testing.T) {
	t.Parallel()

	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{
					Path: "package-lock.json",
					Type: "lockfile",
				},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{
							Name:      "bad\n::warning::INJECTED",
							Version:   "1.0.0",
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

	if strings.Contains(result, "\n::warning::") || strings.Contains(result, "\r::warning::") {
		t.Errorf("GH annotation output contains unescaped line break in message body, enabling workflow command injection.\nOutput: %q", result)
	}
	if !strings.Contains(result, "%0A") {
		t.Errorf("GH annotation output does not contain %%0A encoding for newline.\nOutput: %q", result)
	}
}
