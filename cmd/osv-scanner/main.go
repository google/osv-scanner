package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/osvscanner"

	"github.com/urfave/cli/v2"
)

var (
	// Update this variable when doing a release
	version = "1.2.0"
	commit  = "n/a"
	date    = "n/a"
)

func run(args []string, stdout, stderr io.Writer) int {
	var r *output.Reporter

	cli.VersionPrinter = func(ctx *cli.Context) {
		r = output.NewReporter(ctx.App.Writer, ctx.App.ErrWriter, "")
		r.PrintText(fmt.Sprintf("osv-scanner version: %s\ncommit: %s\nbuilt at: %s\n", ctx.App.Version, commit, date))
	}

	app := &cli.App{
		Name:      "osv-scanner",
		Version:   version,
		Usage:     "scans various mediums for dependencies and matches it against the OSV database",
		Suggest:   true,
		Writer:    stdout,
		ErrWriter: stderr,
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
				Usage:   "sets the output format",
				Value:   "table",
				Action: func(context *cli.Context, s string) error {
					switch s {
					case
						"table",
						"json",
						"markdown":
						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: \"table\", \"json\", \"markdown\"", s)
				},
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "sets output to json (deprecated, use --format json instead)",
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
				Usage: "attempt call analysis on code to detect only active vulnerabilities",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "no-ignore",
				Usage: "also scan files that would be ignored by .gitignore",
				Value: false,
			},
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(context *cli.Context) error {
			format := context.String("format")

			if context.Bool("json") {
				format = "json"
			}

			r = output.NewReporter(stdout, stderr, format)

			vulnResult, err := osvscanner.DoScan(osvscanner.ScannerActions{
				LockfilePaths:            context.StringSlice("lockfile"),
				SBOMPaths:                context.StringSlice("sbom"),
				DockerContainerNames:     context.StringSlice("docker"),
				Recursive:                context.Bool("recursive"),
				SkipGit:                  context.Bool("skip-git"),
				NoIgnore:                 context.Bool("no-ignore"),
				ConfigOverridePath:       context.String("config"),
				DirectoryPaths:           context.Args().Slice(),
				ExperimentalCallAnalysis: context.Bool("experimental-call-analysis"),
			}, r)

			if errPrint := r.PrintResult(&vulnResult); errPrint != nil {
				return fmt.Errorf("failed to write output: %w", errPrint)
			}
			//nolint:wrapcheck
			return err
		},
	}

	if err := app.Run(args); err != nil {
		if r == nil {
			r = output.NewReporter(stdout, stderr, "")
		}
		if errors.Is(err, osvscanner.VulnerabilitiesFoundErr) {
			return 1
		}

		if errors.Is(err, osvscanner.OnlyUncalledVulnerabilitiesFoundErr) {
			// TODO: Discuss whether to have a different exit code now that running call analysis is not default
			return 2
		}

		if errors.Is(err, osvscanner.NoPackagesFoundErr) {
			r.PrintError("No package sources found, --help for usage information.\n")
			return 128
		}

		r.PrintError(fmt.Sprintf("%v\n", err))
	}

	// if we've been told to print an error, and not already exited with
	// a specific error code, then exit with a generic non-zero code
	if r != nil && r.HasPrintedError() {
		return 127
	}

	return 0
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}
