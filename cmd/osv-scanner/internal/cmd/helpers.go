// Package cmd provides helper functions for the osv-scanner CLI commands.
package cmd

import (
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan"
	"github.com/urfave/cli/v3"
)

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
func warnIfCommandAmbiguous(command, defaultCommand string, stderr io.Writer) {
	if _, err := os.Stat(command); err == nil {
		// todo this should be using slog.Warn, maybe...
		fmt.Fprintf(stderr, "Warning: `%[1]s` exists as both a subcommand of OSV-Scanner and as a file on the filesystem. "+
			"`%[1]s` is assumed to be a subcommand here. If you intended for `%[1]s` to be an argument to `%[2]s`, "+
			"you must specify `%[2]s %[1]s` in your command line.\n", command, defaultCommand)
	}
}

// Inserts the default command to args if no command is specified.
func insertDefaultCommand(args []string, commands []*cli.Command, defaultCommand string, stderr io.Writer) []string {
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

	warnIfCommandAmbiguous(command, defaultCommand, stderr)

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
		warnIfCommandAmbiguous(subcommand, scan.DefaultSubcommand, stderr)
	}

	return args
}
