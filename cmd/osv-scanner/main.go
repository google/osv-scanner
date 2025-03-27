package main

import (
	"os"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
)

func main() {
	os.Exit(
		cmd.Run(os.Args, os.Stdout, os.Stderr),
	)
}
