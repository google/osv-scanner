package cmd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"

	scalibr "github.com/google/osv-scalibr/version"
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
	// urfave/cli uses a global for its help flag which makes it possible for a nil
	// pointer dereference if running in a parallel setting, which our test suite
	// does, so this is used to hide the help flag so the global won't be used
	// unless a particular env variable is set
	//
	// see https://github.com/urfave/cli/issues/2176
	shouldHideHelp := testing.Testing() && os.Getenv("TEST_SHOW_HELP") != "true"

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
		cmdlogger.Infof("osv-scanner version: %s", cmd.Version)
		cmdlogger.Infof("osv-scalibr version: %s", scalibr.ScannerVersion)
		cmdlogger.Infof("commit: %s", commit)
		cmdlogger.Infof("built at: %s", date)
	}

	cmds := make([]*cli.Command, 0, len(commands))
	for _, cmd := range commands {
		c := cmd(stdout, stderr)
		c.HideHelp = shouldHideHelp

		cmds = append(cmds, c)
	}

	app := &cli.Command{
		Name:           "osv-scanner",
		Version:        version.OSVVersion,
		Usage:          "scans various mediums for dependencies and checks them against the OSV database",
		Suggest:        true,
		HideHelp:       shouldHideHelp,
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
			cmdlogger.Errorf("No package sources found, --help for usage information.")
			return 128
		case errors.Is(err, osvscanner.ErrAPIFailed):
			cmdlogger.Errorf("%v", err)
			return 129
		}
		cmdlogger.Errorf("%v", err)
	}

	// if we've been told to print an error, and not already exited with
	// a specific error code, then exit with a generic non-zero code
	if logHandler.HasErrored() {
		return 127
	}

	return 0
}
