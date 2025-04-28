package main

import (
	"os"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/update"
)

func main() {
	os.Exit(
		cmd.Run(os.Args, os.Stdout, os.Stderr, []cmd.CommandBuilder{
			scan.Command,
			fix.Command,
			update.Command,
		}),
	)
}
