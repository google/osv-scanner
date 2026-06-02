package output_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func init() {
	// Set a fixed time for deterministic snapshot testing
	output.GitlabTimeNow = func() time.Time {
		return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	}
}

func TestPrintGitLabResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGitLabResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintGitLabResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGitLabResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintGitLabResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintGitLabResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}
