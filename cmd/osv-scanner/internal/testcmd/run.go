package testcmd

import (
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func run(t *testing.T, tc Case) (string, string) {
	t.Helper()

	stdout := newMuffledWriter()
	stderr := newMuffledWriter()

	ec := cmd.Run(tc.Args, stdout, stderr)

	if ec != tc.Exit {
		t.Errorf("cli exited with code %d, not %d", ec, tc.Exit)
	}

	return stdout.String(), stderr.String()
}

func Run(t *testing.T, tc Case) {
	t.Helper()

	stdout, stderr := run(t, tc)

	if tc.isOutputtingJSON() {
		stdout = testutility.NormalizeJSON(t, stdout, tc.ReplaceRules...)
	}

	testutility.NewSnapshot().MatchText(t, stdout)
	testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
		"CreateFile": "stat",
	}).MatchText(t, stderr)
}
