package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/jedib0t/go-pretty/v6/text"
)

func TestPrintVerticalResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintVerticalResults(args.vulnResult, outputWriter)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintVerticalResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintVerticalResults(args.vulnResult, outputWriter)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintVerticalResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintVerticalResults(args.vulnResult, outputWriter)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}
