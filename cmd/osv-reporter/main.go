package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/osv-scanner/internal/ci"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

var (
	// Update this variable when doing a release
	commit = "n/a"
	date   = "n/a"
)

// splitLastArg splits the last argument by new lines and appends the split
// elements onto args and returns it
func splitLastArg(args []string) []string {
	lastArg := args[len(args)-1]
	lastArgSplits := strings.Split(lastArg, "\n")
	args = append(args[:len(args)-1], lastArgSplits...)

	return args
}

func run(args []string, stdout, stderr io.Writer) int {
	var tableReporter reporter.Reporter

	// Allow multiple arguments to be defined by github actions by splitting the last argument
	// by new lines.
	args = splitLastArg(args)

	cli.VersionPrinter = func(ctx *cli.Context) {
		// Use the app Writer and ErrWriter since they will be the writers to keep parallel tests consistent
		tableReporter = reporter.NewTableReporter(ctx.App.Writer, ctx.App.ErrWriter, false, 0)
		tableReporter.PrintText(fmt.Sprintf("osv-scanner version: %s\ncommit: %s\nbuilt at: %s\n", ctx.App.Version, commit, date))
	}

	app := &cli.App{
		Name:        "osv-scanner-action-reporter",
		Version:     version.OSVVersion,
		Usage:       "(Experimental) generates github action output",
		Description: "(Experimental) Used specifically to generate github action output ",
		Suggest:     true,
		Writer:      stdout,
		ErrWriter:   stderr,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "old",
				Usage:       "the old osv json output",
				TakesFile:   true,
				Required:    false,
				DefaultText: "",
			},
			&cli.StringFlag{
				Name:      "new",
				Usage:     "the new osv json output",
				TakesFile: true,
				Required:  true,
			},
			&cli.StringFlag{
				Name:      "output",
				Usage:     "saves the SARIF result to the given file path",
				TakesFile: true,
			},
			&cli.BoolFlag{
				Name:  "gh-annotations",
				Usage: "prints github action annotations",
			},
		},
		Action: func(context *cli.Context) error {
			var termWidth int
			var err error
			if stdoutAsFile, ok := stdout.(*os.File); ok {
				termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
				if err != nil { // If output is not a terminal,
					termWidth = 0
				}
			}

			if tableReporter, err = reporter.New("table", stdout, stderr, termWidth); err != nil {
				return err
			}

			oldPath := context.String("old")
			newPath := context.String("new")

			oldVulns := models.VulnerabilityResults{}
			if oldPath != "" {
				oldVulns, err = ci.LoadVulnResults(oldPath)
				if err != nil {
					return fmt.Errorf("failed to open old results at %s: %w", oldPath, err)
				}
			}

			newVulns, err := ci.LoadVulnResults(newPath)
			if err != nil {
				return fmt.Errorf("failed to open new results at %s: %w", newPath, err)
			}

			var diffVulns models.VulnerabilityResults

			diffVulnOccurrences := ci.DiffVulnerabilityResultsByOccurrences(oldVulns, newVulns)
			if len(diffVulnOccurrences) == 0 {
				// There are actually no new vulns, no need to do full diff
				//
				// Since `DiffVulnerabilityResultsByUniqueVulnCount` does not account for Source or Package,
				// this actually changes the results in some cases, e.g.
				//
				// When a lockfile is moved, `DiffVulnerabilityResults` will report the moved lockfile as having
				// a new vulnerability if the existing lockfile has a vulnerability. However this check will
				// report no vulnerabilities. This is desired behavior.

				// TODO: This will need to be not empty when we change osv-scanner to report all packages
				diffVulns = models.VulnerabilityResults{}
			} else {
				// TODO: This will need to contain all scanned packages when we change osv-scanner to report all packages
				diffVulns = ci.DiffVulnerabilityResults(oldVulns, newVulns)
			}

			if errPrint := tableReporter.PrintResult(&diffVulns); errPrint != nil {
				return fmt.Errorf("failed to write output: %w", errPrint)
			}

			if context.Bool("gh-annotations") {
				var ghAnnotationsReporter reporter.Reporter
				if ghAnnotationsReporter, err = reporter.New("gh-annotations", stdout, stderr, termWidth); err != nil {
					return err
				}

				if errPrint := ghAnnotationsReporter.PrintResult(&diffVulns); errPrint != nil {
					return fmt.Errorf("failed to write output: %w", errPrint)
				}
			}

			outputPath := context.String("output")
			if outputPath != "" {
				var err error
				stdout, err = os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				termWidth = 0
				var sarifReporter reporter.Reporter
				if sarifReporter, err = reporter.New("sarif", stdout, stderr, termWidth); err != nil {
					return err
				}

				if errPrint := sarifReporter.PrintResult(&diffVulns); errPrint != nil {
					return fmt.Errorf("failed to write output: %w", errPrint)
				}
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
		if tableReporter == nil {
			tableReporter = reporter.NewTableReporter(stdout, stderr, false, 0)
		}
		if errors.Is(err, osvscanner.VulnerabilitiesFoundErr) {
			return 1
		}

		if errors.Is(err, osvscanner.OnlyUncalledVulnerabilitiesFoundErr) {
			// TODO: Discuss whether to have a different exit code now that running call analysis is not default
			return 2
		}

		if errors.Is(err, osvscanner.NoPackagesFoundErr) {
			tableReporter.PrintError("No package sources found, --help for usage information.\n")
			return 128
		}

		tableReporter.PrintError(fmt.Sprintf("%v\n", err))
	}

	// if we've been told to print an error, and not already exited with
	// a specific error code, then exit with a generic non-zero code
	if tableReporter != nil && tableReporter.HasPrintedError() {
		return 127
	}

	return 0
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}
