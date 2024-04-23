package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/testutility"
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
