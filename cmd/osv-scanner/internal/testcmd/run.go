package testcmd

import (
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/update"
	"github.com/urfave/cli/v2"
)

func Run(t *testing.T, tc Case) (string, string) {
	t.Helper()

	stdout := newMuffledWriter()
	stderr := newMuffledWriter()

	ec := cmd.Run(tc.Args, stdout, stderr, []*cli.Command{
		scan.Command(stdout, stderr),
		fix.Command(stdout, stderr),
		update.Command(),
	})

	if ec != tc.Exit {
		t.Errorf("cli exited with code %d, not %d", ec, tc.Exit)
	}

	return stdout.String(), stderr.String()
}
