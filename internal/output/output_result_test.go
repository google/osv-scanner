package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/testutility"
)

func TestPrintOutputResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}
