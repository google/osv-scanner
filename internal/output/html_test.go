package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/internal/output"
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
