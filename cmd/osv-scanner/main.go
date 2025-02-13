package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/update"
	"github.com/google/osv-scanner/v2/internal/clilogger"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v2"
)

var (
	commit = "n/a"
	date   = "n/a"
)

func run(args []string, stdout, stderr io.Writer) int {
	logger := clilogger.New(stdout, stderr)

	slog.SetDefault(slog.New(&logger))

	cli.VersionPrinter = func(ctx *cli.Context) {
		slog.Info(fmt.Sprintf("osv-scanner version: %s\ncommit: %s\nbuilt at: %s\n", ctx.App.Version, commit, date))
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

	args = insertDefaultCommand(args, app.Commands, app.DefaultCommand)

	if err := app.Run(args); err != nil {
		switch {
		case errors.Is(err, osvscanner.ErrVulnerabilitiesFound):
			return 1
		case errors.Is(err, osvscanner.ErrNoPackagesFound):
			slog.Error(fmt.Sprintf("No package sources found, --help for usage information.\n"))
			return 128
		case errors.Is(err, osvscanner.ErrAPIFailed):
			slog.Error(fmt.Sprintf("%v\n", err))
			return 129
		}
		slog.Error(fmt.Sprintf("%v\n", err))
	}

	// if we've been told to print an error, and not already exited with
	// a specific error code, then exit with a generic non-zero code
	if logger.HasErrored() {
		return 127
	}

	return 0
}

func getCustomHelpTemplate() string {
	return `
NAME:
	{{.Name}} - {{.Usage}}

USAGE:
	{{.Name}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}}

EXAMPLES:
	# Scan a source directory
	$ {{.Name}} scan source -r <source_directory>

	# Scan a source directory in offline mode
	$ {{.Name}} scan source --offline-vulnerabilities --download-offline-database -r <source_directory>

	# Scan a container image
	$ {{.Name}} scan image <image_name>

	# Scan a local image archive (e.g. a tar file) and generate HTML output
	$ {{.Name}} scan image --serve --archive <image_name.tar>

	# Fix vulnerabilities in a manifest file and lockfile (non-interactive mode)
	$ {{.Name}} fix -M <manifest_file> -L <lockfile>

	For full usage details, please refer to the help command of each subcommand (e.g. {{.Name}} scan --help).

VERSION:
	{{.Version}}

COMMANDS:
{{range .Commands}}{{if and (not .HideHelp) (not .Hidden)}}  {{join .Names ", "}}{{ "\t"}}{{.Usage}}{{ "\n" }}{{end}}{{end}}
{{if .VisibleFlags}}
GLOBAL OPTIONS:
	{{range .VisibleFlags}}  {{.}}{{end}}
{{end}}
`
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

// warnIfCommandAmbiguous warns the user if the command they are trying to run
// exists as both a subcommand and as a file on the filesystem.
// If this is the case, the command is assumed to be a subcommand.
func warnIfCommandAmbiguous(command, defaultCommand string) {
	if _, err := os.Stat(command); err == nil {
		slog.Warn(fmt.Sprintf("Warning: `%[1]s` exists as both a subcommand of OSV-Scanner and as a file on the filesystem. "+
			"`%[1]s` is assumed to be a subcommand here. If you intended for `%[1]s` to be an argument to `%[2]s`, "+
			"you must specify `%[2]s %[1]s` in your command line.\n", command, defaultCommand))
	}
}

// Inserts the default command to args if no command is specified.
func insertDefaultCommand(args []string, commands []*cli.Command, defaultCommand string) []string {
	// Do nothing if no command or file name is provided.
	if len(args) < 2 {
		return args
	}

	allCommands := getAllCommands(commands)
	command := args[1]
	// If no command is provided, use the default command and subcommand.
	if !slices.Contains(allCommands, command) {
		// Avoids modifying args in-place, as some unit tests rely on its original value for multiple calls.
		argsTmp := make([]string, len(args)+2)
		copy(argsTmp[3:], args[1:])
		argsTmp[1] = defaultCommand
		// Set the default subCommand of Scan
		argsTmp[2] = scan.DefaultSubcommand

		// Executes the cli app with the new args.
		return argsTmp
	}

	warnIfCommandAmbiguous(command, defaultCommand)

	// If only the default command is provided without its subcommand, append the subcommand.
	if command == defaultCommand {
		if len(args) < 3 {
			// Indicates that only "osv-scanner scan" was provided, without a subcommand or filename
			return args
		}

		subcommand := args[2]
		// Default to the "source" subcommand if none is provided.
		if !slices.Contains(scan.Subcommands, subcommand) {
			argsTmp := make([]string, len(args)+1)
			copy(argsTmp[3:], args[2:])
			argsTmp[1] = defaultCommand
			argsTmp[2] = scan.DefaultSubcommand

			return argsTmp
		}

		// Print a warning message if subcommand exist on the filesystem.
		warnIfCommandAmbiguous(subcommand, scan.DefaultSubcommand)
	}

	return args
}

func main() {
	exitCode := run(os.Args, os.Stdout, os.Stderr)

	os.Exit(exitCode)
}
