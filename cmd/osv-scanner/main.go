package main

import (
	"io"
	"os"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/update"
	"github.com/urfave/cli/v2"
)

var (
	commit = "n/a"
	date   = "n/a"
)

func run(args []string, stdout, stderr io.Writer) int {
	return cmd.Run(args, stdout, stderr, []*cli.Command{
		scan.Command(stdout, stderr),
		fix.Command(stdout, stderr),
		update.Command(),
	})
}

func main() {
	exitCode := run(os.Args, os.Stdout, os.Stderr)

	os.Exit(exitCode)
}
