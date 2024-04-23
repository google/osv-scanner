package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func TestPrintJSONResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, vulnResult *models.VulnerabilityResults) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintJSONResults(vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing JSON output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintJSONResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, vulnResult *models.VulnerabilityResults) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintJSONResults(vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing JSON output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintJSONResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, vulnResult *models.VulnerabilityResults) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintJSONResults(vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing JSON output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}
