package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/osv-scanner/internal/osvscanner_internal"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/term"
)

var (
	// Update this variable when doing a release
	version = "1.3.5"
	commit  = "n/a"
	date    = "n/a"
)

func run(args []string, stdout, stderr io.Writer) int {
	var r reporter.Reporter

	cli.VersionPrinter = func(ctx *cli.Context) {
		// Use the app Writer and ErrWriter since they will be the writers to keep parallel tests consistent
		r = reporter.NewTableReporter(ctx.App.Writer, ctx.App.ErrWriter, false, 0)
		r.PrintText(fmt.Sprintf("osv-scanner version: %s\ncommit: %s\nbuilt at: %s\n", ctx.App.Version, commit, date))
	}

	app := &cli.App{
		Name:        "osv-scanner-diff",
		Version:     version,
		Usage:       "compares the output of multiple osv-scanner runs to find new vulnerabilities",
		Description: "Remove vulnerabilities in the old OSV JSON output from the new OSV JSON output",
		Suggest:     true,
		Writer:      stdout,
		ErrWriter:   stderr,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      "old",
				Usage:     "the old osv json output",
				TakesFile: true,
				Required:  true,
			},
			&cli.StringFlag{
				Name:      "new",
				Usage:     "the new osv json output",
				TakesFile: true,
				Required:  true,
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "sets the output format",
				Value:   "table",
				Action: func(context *cli.Context, s string) error {
					if slices.Contains(reporter.Format(), s) {
						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
				},
			},
			&cli.StringFlag{
				Name:      "output",
				Usage:     "saves the result to the given file path",
				TakesFile: true,
			},
		},
		Action: func(context *cli.Context) error {
			format := context.String("format")

			outputPath := context.String("output")
			if outputPath != "" {
				var err error
				stdout, err = os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
			}

			var termWidth int
			if outputPath != "" {
				var err error
				termWidth, _, err = term.GetSize(int(os.Stdout.Fd()))
				if err != nil { // If output is not a terminal,
					termWidth = 0
				}
			} else { // Output is a file
				termWidth = 0
			}

			var err error
			if r, err = reporter.New(format, stdout, stderr, termWidth); err != nil {
				return err
			}

			oldPath := context.String("old")
			newPath := context.String("new")

			oldVulns, err := osvscanner_internal.LoadVulnResults(oldPath)
			if err != nil {
				return fmt.Errorf("failed to open old results at %s: %w", oldPath, err)
			}

			newVulns, err := osvscanner_internal.LoadVulnResults(newPath)
			if err != nil {
				return fmt.Errorf("failed to open new results at %s: %w", newPath, err)
			}

			diffVulns := osvscanner_internal.DiffVulnerabilityResults(oldVulns, newVulns)

			if errPrint := r.PrintResult(&diffVulns); errPrint != nil {
				return fmt.Errorf("failed to write output: %w", errPrint)
			}

			// if vulnerability exists it should return error
			if len(diffVulns.Results) > 0 {
				// If any vulnerabilities are called, then we return VulnerabilitiesFoundErr
				for _, vf := range diffVulns.Flatten() {
					if vf.GroupInfo.IsCalled() {
						return osvscanner.VulnerabilitiesFoundErr
					}
				}
				// Otherwise return OnlyUncalledVulnerabilitiesFoundErr
				return osvscanner.OnlyUncalledVulnerabilitiesFoundErr
			}

			return nil
		},
	}

	if err := app.Run(args); err != nil {
		if r == nil {
			r = reporter.NewTableReporter(stdout, stderr, false, 0)
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
