package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"golang.org/x/term"

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
		r = reporter.NewTableReporter(ctx.App.Writer, ctx.App.ErrWriter, false, 0)
		r.PrintTextf("osv-scanner version: %s\ncommit: %s\nbuilt at: %s\n", ctx.App.Version, commit, date)
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
				Name:    "debug",
				Aliases: []string{"d"},
				Usage:   "debug logs",
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
			&cli.BoolFlag{
				Name:  "experimental-only-packages",
				Usage: "only collects packages, does not scan for vulnerabilities",
			},
			&cli.BoolFlag{
				Name:  "consider-scan-path-as-root",
				Usage: "Transform package path root to be the scanning path, thus removing any information about the host",
			},
			&cli.BoolFlag{
				Name:  "paths-relative-to-scan-dir",
				Usage: "Same than --consider-scan-path-as-root but reports a path relative to the scan dir (removing the leading path separator)",
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

			if context.Bool("experimental-licenses-summary") && context.IsSet("experimental-licenses") {
				return fmt.Errorf("--experimental-licenses-summary and --experimental-licenses flags cannot be set")
			}
			allowlist := context.StringSlice("experimental-licenses")
			if context.IsSet("experimental-licenses") &&
				(len(allowlist) == 0 ||
					(len(allowlist) == 1 && allowlist[0] == "")) {
				return fmt.Errorf("--experimental-licenses requires at least one value")
			}
			// TODO: verify that the licenses they passed in are indeed spdx.

			if r, err = reporter.New(format, stdout, stderr, termWidth); err != nil {
				return err
			}

			var callAnalysisStates map[string]bool
			if context.IsSet("experimental-call-analysis") {
				callAnalysisStates = createCallAnalysisStates([]string{"all"}, context.StringSlice("no-call-analysis"))
				r.PrintTextf("Warning: the experimental-call-analysis flag has been replaced. Please use the call-analysis and no-call-analysis flags instead.\n")
			} else {
				callAnalysisStates = createCallAnalysisStates(context.StringSlice("call-analysis"), context.StringSlice("no-call-analysis"))
			}

			vulnResult, err := osvscanner.DoScan(osvscanner.ScannerActions{
				LockfilePaths:          context.StringSlice("lockfile"),
				SBOMPaths:              context.StringSlice("sbom"),
				DockerContainerNames:   context.StringSlice("docker"),
				Recursive:              context.Bool("recursive"),
				SkipGit:                context.Bool("skip-git"),
				NoIgnore:               context.Bool("no-ignore"),
				Debug:                  context.Bool("debug"),
				ConfigOverridePath:     context.String("config"),
				DirectoryPaths:         context.Args().Slice(),
				CallAnalysisStates:     callAnalysisStates,
				ConsiderScanPathAsRoot: context.Bool("consider-scan-path-as-root"),
				PathRelativeToScanDir:  context.Bool("paths-relative-to-scan-dir"),
				ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
					LocalDBPath:    context.String("experimental-local-db-path"),
					CompareLocally: context.Bool("experimental-local-db"),
					CompareOffline: context.Bool("experimental-offline"),
					// License summary mode causes all
					// packages to appear in the json as
					// every package has a license - even
					// if it's just the UNKNOWN license.
					ShowAllPackages: context.Bool("experimental-all-packages") ||
						context.Bool("experimental-licenses-summary"),
					ScanLicensesSummary:   context.Bool("experimental-licenses-summary"),
					ScanLicensesAllowlist: context.StringSlice("experimental-licenses"),
					OnlyPackages:          context.Bool("experimental-only-packages"),
				},
			}, r)

			shouldIgnoreError := errors.Is(err, osvscanner.VulnerabilitiesFoundErr) || errors.Is(err, osvscanner.NoPackagesFoundErr)
			if err != nil && !shouldIgnoreError {
				return err
			}

			if errPrint := r.PrintResult(&vulnResult); errPrint != nil {
				return fmt.Errorf("failed to write output: %w", errPrint)
			}

			// This may be nil.
			return err
		},
	}

	if err := app.Run(args); err != nil {
		if r == nil {
			r = reporter.NewTableReporter(stdout, stderr, false, 0)
		}
		switch {
		case errors.Is(err, osvscanner.VulnerabilitiesFoundErr):
			return 1
		case errors.Is(err, osvscanner.NoPackagesFoundErr):
			r.PrintWarnf("No package sources found, --help for usage information.\n")
			return 0
		}
		r.PrintErrorf("%v\n", err)
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
