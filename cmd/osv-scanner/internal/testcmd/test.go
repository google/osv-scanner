package testcmd

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
)

func Test(t *testing.T, tc Case) {
	t.Helper()

	stdout, stderr := Run(t, tc)

	testutility.NewSnapshot().MatchText(t, stdout)
	testutility.NewSnapshot().MatchText(t, stderr)
}

func TestJSONWithCustomRules(t *testing.T, tc Case) {
	t.Helper()

	stdout, stderr := Run(t, tc)

	testutility.NewSnapshot().MatchOSVScannerJSONOutput(t, stdout, tc.ReplaceRules...)
	testutility.NewSnapshot().MatchText(t, stderr)
}
