package output_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/jedib0t/go-pretty/v6/text"
)

func normalizeSPDXOutput(t *testing.T, str string) string {
	t.Helper()

	str = text.StripEscape(str)
	str = cachedregexp.MustCompile(`"SPDXRef-Package-main-.+"`).ReplaceAllString(str, `"SPDXRef-Package-main-<uuid>"`)
	str = cachedregexp.MustCompile(`"https://spdx.google/.+"`).ReplaceAllString(str, `"https://spdx.google/<uuid>"`)
	str = cachedregexp.MustCompile(`"created": ".+T.+Z"`).ReplaceAllString(str, `"created": "<timestamp>"`)

	return str
}

func TestPrintSPDXResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintSPDXResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, normalizeSPDXOutput(t, outputWriter.String()))
	})
}

func TestPrintSPDXResults_WithLicenseViolations(t *testing.T) {
	t.Parallel()

	testOutputWithLicenseViolations(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintSPDXResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, normalizeSPDXOutput(t, outputWriter.String()))
	})
}

func TestPrintSPDXResults_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintSPDXResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, normalizeSPDXOutput(t, outputWriter.String()))
	})
}
