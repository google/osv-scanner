package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

var (
	commit = "n/a"
	date   = "n/a"
)

type CommandBuilder = func(stdout, stderr io.Writer) *cli.Command

func Run(args []string, stdout, stderr io.Writer, commands []CommandBuilder) int {
	// get rid of the extraneous space in the subcommand help template, as otherwise
	// our snapshots will fail because it will be trailing and removed by editors
	//
	// todo: remove this once https://github.com/urfave/cli/pull/2140 has been released
	cli.SubcommandHelpTemplate = strings.ReplaceAll(
		cli.SubcommandHelpTemplate,
		"{{if .VisibleCommands}} [command [command options]] {{end}}",
		"{{if .VisibleCommands}} [command [command options]]{{end}}",
	)

	// --- Setup Logger ---
	logHandler := cmdlogger.New(stdout, stderr)

	// If in testing mode, set logger via Handler
	// Otherwise, set default global logger
	if testing.Testing() {
		handler, ok := slog.Default().Handler().(*testlogger.Handler)
		if !ok {
			panic("Test failed to initialize default logger with Handler")
		}

		handler.AddInstance(logHandler)
		defer handler.Delete()
	} else {
		slog.SetDefault(slog.New(logHandler))
	}
	// ---

	cli.VersionPrinter = func(cmd *cli.Command) {
		slog.Info("osv-scanner version: " + cmd.Version)
		slog.Info("commit: " + commit)
		slog.Info("built at: " + date)
	}

	cmds := make([]*cli.Command, 0, len(commands))
	for _, cmd := range commands {
		cmds = append(cmds, cmd(stdout, stderr))
	}

	app := &cli.Command{
		Name:           "osv-scanner",
		Version:        version.OSVVersion,
		Usage:          "scans various mediums for dependencies and checks them against the OSV database",
		Suggest:        true,
		Writer:         stdout,
		ErrWriter:      stderr,
		DefaultCommand: "scan",
		Commands:       cmds,

		CustomRootCommandHelpTemplate: getCustomHelpTemplate(),
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
	app.ExitErrHandler = func(_ context.Context, _ *cli.Command, _ error) {}

	args = insertDefaultCommand(args, app.Commands, app.DefaultCommand, stderr)

	err := app.Run(context.Background(), args)

	// if the config is invalid, it's possible that is why any other errors
	// happened so that exit code takes priority
	if logHandler.HasErroredBecauseInvalidConfig() {
		return 130
	}

	if err != nil {
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
	if logHandler.HasErrored() {
		return 127
	}

	return 0
}
