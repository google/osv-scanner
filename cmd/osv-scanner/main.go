package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scanner/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"

	"github.com/urfave/cli/v2"
)

var (
	commit = "n/a"
	date   = "n/a"
)

func run(args []string, stdout, stderr io.Writer) int {
	var r reporter.Reporter

	cli.VersionPrinter = func(ctx *cli.Context) {
		// Use the app Writer and ErrWriter since they will be the writers to keep parallel tests consistent
		r = reporter.NewTableReporter(ctx.App.Writer, ctx.App.ErrWriter, reporter.InfoLevel, false, 0)
		r.Infof("osv-scanner version: %s\ncommit: %s\nbuilt at: %s\n", ctx.App.Version, commit, date)
	}

	osv.RequestUserAgent = "osv-scanner/" + version.OSVVersion

	app := &cli.App{
		Name:           "osv-scanner",
		Version:        version.OSVVersion,
		Usage:          "scans various mediums for dependencies and matches it against the OSV database",
		Suggest:        true,
		Writer:         stdout,
		ErrWriter:      stderr,
		DefaultCommand: "scan",
		Commands: []*cli.Command{
			{
				Name:        "scan",
				Usage:       "scans various mediums for dependencies and matches it against the OSV database",
				Description: "scans various mediums for dependencies and matches it against the OSV database",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:      "docker",
						Aliases:   []string{"D"},
						Usage:     "scan docker image with this name",
						TakesFile: false,
					},
					&cli.StringSliceFlag{
						Name:      "lockfile",
						Aliases:   []string{"L"},
						Usage:     "scan package lockfile on this path",
						TakesFile: true,
					},
					&cli.StringSliceFlag{
						Name:      "sbom",
						Aliases:   []string{"S"},
						Usage:     "scan sbom file on this path",
						TakesFile: true,
					},
					&cli.StringFlag{
						Name:      "config",
						Usage:     "set/override config file",
						TakesFile: true,
					},
					&cli.StringFlag{
						Name:    "format",
						Aliases: []string{"f"},
						Usage:   fmt.Sprintf("sets the output format; value can be: %s", strings.Join(reporter.Format(), ", ")),
						Value:   "table",
						Action: func(context *cli.Context, s string) error {
							if slices.Contains(reporter.Format(), s) {
								return nil
							}

							return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
						},
					},
					&cli.BoolFlag{
						Name:  "json",
						Usage: "sets output to json (deprecated, use --format json instead)",
					},
					&cli.StringFlag{
						Name:      "output",
						Usage:     "saves the result to the given file path",
						TakesFile: true,
					},
					&cli.BoolFlag{
						Name:  "skip-git",
						Usage: "skip scanning git repositories",
						Value: false,
					},
					&cli.BoolFlag{
						Name:    "recursive",
						Aliases: []string{"r"},
						Usage:   "check subdirectories",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:  "experimental-call-analysis",
						Usage: "[Deprecated] attempt call analysis on code to detect only active vulnerabilities",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "no-ignore",
						Usage: "also scan files that would be ignored by .gitignore",
						Value: false,
					},
					&cli.StringSliceFlag{
						Name:  "call-analysis",
						Usage: "attempt call analysis on code to detect only active vulnerabilities",
					},
					&cli.StringSliceFlag{
						Name:  "no-call-analysis",
						Usage: "disables call graph analysis",
					},
					&cli.StringFlag{
						Name:  "verbosity",
						Usage: fmt.Sprintf("specify the level of information that should be provided during runtime; value can be: %s", strings.Join(reporter.VerbosityLevels(), ", ")),
						Value: "info",
					},
					&cli.BoolFlag{
						Name:  "experimental-local-db",
						Usage: "checks for vulnerabilities using local databases",
					},
					&cli.BoolFlag{
						Name:  "experimental-offline",
						Usage: "checks for vulnerabilities using local databases that are already cached",
					},
					&cli.StringFlag{
						Name:   "experimental-local-db-path",
						Usage:  "sets the path that local databases should be stored",
						Hidden: true,
					},
					&cli.BoolFlag{
						Name:  "experimental-all-packages",
						Usage: "when json output is selected, prints all packages",
					},
					&cli.BoolFlag{
						Name:  "experimental-licenses-summary",
						Usage: "report a license summary, implying the --experimental-all-packages flag",
					},
					&cli.StringSliceFlag{
						Name:  "experimental-licenses",
						Usage: "report on licenses based on an allowlist",
					},
				},
				ArgsUsage: "[directory1 directory2...]",
				Action: func(c *cli.Context) error {
					return scan.ScanAction(c, stdout, stderr)
				},
			},
			{
				Name:        "fix",
				Usage:       "guided remediation",
				Description: "guided remediation",
			},
			{
				Name:        "update",
				Usage:       "automated updates",
				Description: "automated updates",
			},
		},
	}

	if len(args) >= 2 {
		if args[1] != "scan" && args[1] != "update" && args[1] != "fix" && args[1] != "--help" && args[1] != "--version" {
			args = append(args, "")
			copy(args[2:], args[1:])
			args[1] = "scan"
		}
	}

	if err := app.Run(args); err != nil {
		if r == nil {
			r = reporter.NewTableReporter(stdout, stderr, reporter.InfoLevel, false, 0)
		}
		switch {
		case errors.Is(err, osvscanner.VulnerabilitiesFoundErr):
			return 1
		case errors.Is(err, osvscanner.NoPackagesFoundErr):
			r.Errorf("No package sources found, --help for usage information.\n")
			return 128
		}
		r.Errorf("%v\n", err)
	}

	// if we've been told to print an error, and not already exited with
	// a specific error code, then exit with a generic non-zero code
	if r != nil && r.HasErrored() {
		return 127
	}

	return 0
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}
