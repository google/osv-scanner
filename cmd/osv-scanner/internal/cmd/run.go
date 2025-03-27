package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/update"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v2"
)

var (
	commit = "n/a"
	date   = "n/a"
)

func Run(args []string, stdout, stderr io.Writer) int {
	logger := cmdlogger.New(stdout, stderr)

	slog.SetDefault(slog.New(&logger))

	cli.VersionPrinter = func(ctx *cli.Context) {
		slog.Info("osv-scanner version: " + ctx.App.Version)
		slog.Info("commit: " + commit)
		slog.Info("built at: " + date)
	}

	app := &cli.App{
		Name:           "osv-scanner",
		Version:        version.OSVVersion,
		Usage:          "scans various mediums for dependencies and checks them against the OSV database",
		Suggest:        true,
		Writer:         stdout,
		ErrWriter:      stderr,
		DefaultCommand: "scan",
		Commands: []*cli.Command{
			scan.Command(stdout, stderr),
			fix.Command(stdout, stderr),
			update.Command(),
		},
		CustomAppHelpTemplate: getCustomHelpTemplate(),
	}

	// If ExitErrHandler is not set, cli will use the default cli.HandleExitCoder.
	// This is not ideal as cli.HandleExitCoder checks if the error implements cli.ExitCode interface.
	//
	// 99% of the time, this is fine, as we do not implement cli.ExitCode in our errors, so errors pass through
	// that handler untouched.
	// However, because of Go's duck typing, any error that happens to have a ExitCode() function
	// (e.g. *exec.ExitError) will be assumed to implement cli.ExitCode interface and cause the program to exit
	// early without proper error handling.
	//
	// This removes the handler entirely so that behavior will not unexpectedly happen.
	app.ExitErrHandler = func(_ *cli.Context, _ error) {}

	args = insertDefaultCommand(args, app.Commands, app.DefaultCommand, stderr)

	if err := app.Run(args); err != nil {
		switch {
		case errors.Is(err, osvscanner.ErrVulnerabilitiesFound):
			return 1
		case errors.Is(err, osvscanner.ErrNoPackagesFound):
			slog.Error("No package sources found, --help for usage information.")
			return 128
		case errors.Is(err, osvscanner.ErrAPIFailed):
			slog.Error(fmt.Sprintf("%v", err))
			return 129
		}
		slog.Error(fmt.Sprintf("%v", err))
	}

	// if we've been told to print an error, and not already exited with
	// a specific error code, then exit with a generic non-zero code
	if logger.HasErrored() {
		return 127
	}

	return 0
}
