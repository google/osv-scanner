package main

import (
	"errors"
	"io"
	"os"
	"slices"

	"github.com/google/osv-scanner/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/cmd/osv-scanner/update"
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
		Usage:          "scans various mediums for dependencies and checks them against the OSV database",
		Suggest:        true,
		Writer:         stdout,
		ErrWriter:      stderr,
		DefaultCommand: "scan",
		Commands: []*cli.Command{
			scan.Command(stdout, stderr, &r),
			fix.Command(stdout, stderr, &r),
			update.Command(stdout, stderr, &r),
		},
	}

	args = insertDefaultCommand(args, app.Commands, app.DefaultCommand, stdout, stderr)

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
		case errors.Is(err, osvscanner.ErrAPIFailed):
			r.Errorf("%v\n", err)
			return 129
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

// Gets all valid commands and global options for OSV-Scanner.
func getAllCommands(commands []*cli.Command) []string {
	// Adding all subcommands
	allCommands := make([]string, 0)
	for _, command := range commands {
		allCommands = append(allCommands, command.Name)
	}

	// Adding help command and help flags
	for _, flag := range cli.HelpFlag.Names() {
		allCommands = append(allCommands, flag)      // help command
		allCommands = append(allCommands, "-"+flag)  // help flag
		allCommands = append(allCommands, "--"+flag) // help flag
	}

	// Adding version flags
	for _, flag := range cli.VersionFlag.Names() {
		allCommands = append(allCommands, "-"+flag)
		allCommands = append(allCommands, "--"+flag)
	}

	return allCommands
}

// Inserts the default command to args if no command is specified.
func insertDefaultCommand(args []string, commands []*cli.Command, defaultCommand string, stdout, stderr io.Writer) []string {
	if len(args) < 2 {
		return args
	}

	allCommands := getAllCommands(commands)
	if !slices.Contains(allCommands, args[1]) {
		// Avoids modifying args in-place, as some unit tests rely on its original value for multiple calls.
		argsTmp := make([]string, len(args)+1)
		copy(argsTmp[2:], args[1:])
		argsTmp[1] = defaultCommand

		// Executes the cli app with the new args.
		return argsTmp
	} else if _, err := os.Stat(args[1]); err == nil {
		r := reporter.NewJSONReporter(stdout, stderr, reporter.InfoLevel)
		r.Warnf("Warning: `%[1]s` exists as both a subcommand of OSV-Scanner and as a file on the filesystem. `%[1]s` is assumed to be a subcommand here. If you intended for `%[1]s` to be an argument to `%[1]s`, you must specify `%[1]s %[1]s` in your command line.\n", args[1])
	}

	return args
}

func main() {
	exitCode := run(os.Args, os.Stdout, os.Stderr)

	os.Exit(exitCode)
}
