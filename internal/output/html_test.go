package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestPrintHTMLResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintHTMLResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing HTML output: %s", err)
		}
	})
}

func TestPrintHTMLResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintHTMLResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing HTML output: %s", err)
		}
	})
}

func TestPrintHTMLResults_WithLicenseSummary(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseSummary(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintHTMLResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing HTML output: %s", err)
		}
	})
}

func TestPrintHTMLResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintHTMLResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing HTML output: %s", err)
		}
	})
}

func TestPrintHTMLResults_IncludesScannerVersion(t *testing.T) {
	t.Parallel()

	outputWriter := &bytes.Buffer{}
	err := output.PrintHTMLResults(&models.VulnerabilityResults{}, outputWriter)

	if err != nil {
		t.Fatalf("Error writing HTML output: %s", err)
	}

	want := "OSV-Scanner v" + version.OSVVersion
	if !strings.Contains(outputWriter.String(), want) {
		t.Errorf("expected HTML output to contain %q", want)
	}
}
