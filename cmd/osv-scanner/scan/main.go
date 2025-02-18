package scan

import (
	"io"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/image"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/source"
	"github.com/google/osv-scanner/v2/pkg/reporter"

	"github.com/urfave/cli/v2"
)

const sourceSubCommand = "source"

const DefaultSubcommand = sourceSubCommand

var Subcommands = []string{sourceSubCommand, "image"}

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "scan",
		Usage:       "scans projects and container images for dependencies, and checks them against the OSV database.",
		Description: "scans projects and container images for dependencies, and checks them against the OSV database.",
		Subcommands: []*cli.Command{
			source.Command(stdout, stderr, r),
			image.Command(stdout, stderr, r),
		},
	}
}
