package testcmd

import (
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
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
