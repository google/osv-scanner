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
					var err error
					r, err = scan.ScanAction(c, stdout, stderr)

					return err
				},
			},
		},
	}
	allCommands := getAllCommands(app.Commands)
	if len(args) >= 2 {
		// Insert the default command to args if no command is specified.
		if !slices.Contains(allCommands, args[1]) {
			// Avoid in-place change to args as it is not a pointer.
			argsTmp := make([]string, len(args)+1)
			copy(argsTmp[2:], args[1:])
			argsTmp[1] = app.DefaultCommand
			args = argsTmp
		} else if _, err := os.Stat(args[1]); err == nil {
			if r == nil {
				r = reporter.NewTableReporter(stdout, stderr, reporter.InfoLevel, false, 0)
			}
			r.Infof("Warning: '%v' exists as both a subcommand of OSV-Scanner and as a file in the filesystem. It operates as a command here. If you intend to scan the file, please specify a subcommand.\n", args[1])
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

func getAllCommands(commands []*cli.Command) []string {
	allCommands := make([]string, 0)
	for _, command := range commands {
		allCommands = append(allCommands, command.Name)
	}
	// Adding all global options and help commands
	allCommands = append(allCommands, "--"+cli.VersionFlag.(*cli.BoolFlag).Name)
	allCommands = append(allCommands, "-"+cli.VersionFlag.(*cli.BoolFlag).Aliases[0])
	allCommands = append(allCommands, "--"+cli.HelpFlag.(*cli.BoolFlag).Name)
	allCommands = append(allCommands, cli.HelpFlag.(*cli.BoolFlag).Name)
	allCommands = append(allCommands, "-"+cli.HelpFlag.(*cli.BoolFlag).Aliases[0])
	allCommands = append(allCommands, cli.HelpFlag.(*cli.BoolFlag).Aliases[0])

	return allCommands
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}
