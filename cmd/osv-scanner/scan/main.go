package scan

import (
	"io"

	"github.com/google/osv-scanner/cmd/osv-scanner/scan/docker"
	"github.com/google/osv-scanner/cmd/osv-scanner/scan/project"
	"github.com/google/osv-scanner/pkg/reporter"

	"github.com/urfave/cli/v2"
)

const projectSubCommand = "project"

const DefaultSubcommand = projectSubCommand

var Subcommands = []string{projectSubCommand, "docker"}

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "scan",
		Usage:       "scans projects and Docker images for dependencies, and checks them against the OSV database.",
		Description: "scans projects and Docker images for dependencies, and checks them against the OSV database.",
		Subcommands: []*cli.Command{
			project.Command(stdout, stderr, r),
			docker.Command(stdout, stderr, r),
		},
	}
}
