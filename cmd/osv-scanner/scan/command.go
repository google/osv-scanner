// Package scan implements the `scan` command for osv-scanner.
package scan

import (
	"io"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/image"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/source"
	"github.com/urfave/cli/v3"
)

const sourceSubCommand = "source"

const DefaultSubcommand = sourceSubCommand

var Subcommands = []string{sourceSubCommand, "image"}

func Command(stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "scan",
		Usage:       "scans projects and container images for dependencies, and checks them against the OSV database.",
		Description: "scans projects and container images for dependencies, and checks them against the OSV database.",
		Commands: []*cli.Command{
			source.Command(stdout, stderr),
			image.Command(stdout, stderr),
		},
	}
}
