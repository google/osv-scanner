package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/google/osv-scanner/internal/exclusions"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"golang.org/x/exp/slices"
	"golang.org/x/term"

	"github.com/urfave/cli/v2"
)

var (
	commit = "n/a"
	date   = "n/a"
)

func run(args []string, stdout, stderr io.Writer) int {
	var r reporter.Reporter
	var parsedExclusions []*regexp.Regexp

	cli.VersionPrinter = func(ctx *cli.Context) {
		// Use the app Writer and ErrWriter since they will be the writers to keep parallel tests consistent
		r = reporter.NewTableReporter(ctx.App.Writer, ctx.App.ErrWriter, false, 0)
		r.PrintText(fmt.Sprintf("osv-scanner version: %s\ncommit: %s\nbuilt at: %s\n", ctx.App.Version, commit, date))
	}

	osv.RequestUserAgent = "osv-scanner/" + version.OSVVersion

	app := &cli.App{
		Name:      "osv-scanner",
		Version:   version.OSVVersion,
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
				Usage: "attempt call analysis on code to detect only active vulnerabilities",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "no-ignore",
				Usage: "also scan files that would be ignored by .gitignore",
				Value: false,
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
			&cli.StringSliceFlag{
				Name:  "exclude-packages",
				Usage: "list of regex patterns to exclude from scanning",
				Action: func(context *cli.Context, s []string) error {
					err := exclusions.IsRegexPatterns(s)
					if err != nil {
						return fmt.Errorf("invalid regex pattern: %w", err)
					}

					return nil
				},
			},
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(context *cli.Context) error {
			format := context.String("format")

			if context.Bool("json") {
				format = "json"
			}

			outputPath := context.String("output")

			termWidth := 0
			var err error
			if outputPath != "" { // Output is definitely a file
				stdout, err = os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
			} else { // Output might be a terminal
				if stdoutAsFile, ok := stdout.(*os.File); ok {
					termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
					if err != nil { // If output is not a terminal,
						termWidth = 0
					}
				}
			}

			if r, err = reporter.New(format, stdout, stderr, termWidth); err != nil {
				return err
			}

			if context.StringSlice("exclude-packages") != nil {
				parsedExclusions, err = exclusions.ParseExclusions(context.StringSlice("exclude-packages")) // Parse our list of regex patterns into a list of regex objects
				if err != nil {
					return fmt.Errorf("invalid exclusion pattern: %w", err)
				}
			}

			vulnResult, err := osvscanner.DoScan(osvscanner.ScannerActions{
				LockfilePaths:        context.StringSlice("lockfile"),
				SBOMPaths:            context.StringSlice("sbom"),
				DockerContainerNames: context.StringSlice("docker"),
				Recursive:            context.Bool("recursive"),
				SkipGit:              context.Bool("skip-git"),
				NoIgnore:             context.Bool("no-ignore"),
				ConfigOverridePath:   context.String("config"),
				DirectoryPaths:       context.Args().Slice(),
				Exclusions:           parsedExclusions,
				ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
					LocalDBPath:    context.String("experimental-local-db-path"),
					CallAnalysis:   context.Bool("experimental-call-analysis"),
					CompareLocally: context.Bool("experimental-local-db"),
					CompareOffline: context.Bool("experimental-offline"),
				},
			}, r)

			if err != nil &&
				!errors.Is(err, osvscanner.VulnerabilitiesFoundErr) &&
				!errors.Is(err, osvscanner.OnlyUncalledVulnerabilitiesFoundErr) {
				//nolint:wrapcheck
				return err
			}

			if errPrint := r.PrintResult(&vulnResult); errPrint != nil {
				return fmt.Errorf("failed to write output: %w", errPrint)
			}

			// Could be nil, VulnerabilitiesFoundErr, or OnlyUncalledVulnerabilitiesFoundErr
			return err
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
