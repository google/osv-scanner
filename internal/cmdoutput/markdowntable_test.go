package cmdoutput_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cmdoutput"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestPrintMarkdownTableResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		cmdoutput.PrintMarkdownTableResults(args.vulnResult, outputWriter)

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintMarkdownTableResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		cmdoutput.PrintMarkdownTableResults(args.vulnResult, outputWriter)

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintMarkdownTableResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		cmdoutput.PrintMarkdownTableResults(args.vulnResult, outputWriter)

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}
