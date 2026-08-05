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

// TestPrintGHAnnotationReport_Escaping verifies that characters like %, \r, \n, :, and ,
// are correctly escaped in command properties and command data according to GitHub Actions docs.
func TestPrintGHAnnotationReport_Escaping(t *testing.T) {
	t.Parallel()

	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{
					Path: "file,with:colon%and\r\nnewlines.json",
					Type: "lockfile",
				},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{
							Name:      "pkg,with:colon%and\r\nnewlines",
							Version:   "1.0.0",
							Ecosystem: "npm",
						},
						Groups: []models.GroupInfo{
							{
								IDs:         []string{"GHSA-1234"},
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

	// Verify property escaping in the file= attribute
	// file,with:colon%and\r\nnewlines.json -> file%2Cwith%3Acolon%25and%0D%0Anewlines.json
	expectedProperty := "file%2Cwith%3Acolon%25and%0D%0Anewlines.json"
	if !strings.Contains(result, "file="+expectedProperty+"::") {
		t.Errorf("GH annotation output property not escaped properly.\nExpected property: %s\nOutput: %q", expectedProperty, result)
	}

	// Verify data escaping for % character in the message content
	// The % should be escaped to %25
	if !strings.Contains(result, "%25") {
		t.Errorf("GH annotation output data does not contain %%25 encoding for %% character.\nOutput: %q", result)
	}

	// Verify data escaping for \r\n in the message content
	// The \r\n should be escaped to %0D%0A
	if !strings.Contains(result, "%0D%0A") {
		t.Errorf("GH annotation output data does not contain %%0D%%0A encoding for \\r\\n character.\nOutput: %q", result)
	}

	// Verify that raw %, \r, \n are not present in the file property
	if strings.Contains(result, "file=file,with:colon%and") {
		t.Errorf("GH annotation output property contains unescaped special characters.\nOutput: %q", result)
	}
}

