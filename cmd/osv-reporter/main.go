package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/google/osv-scanner/v2/internal/ci"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/reporter"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
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
	logger := cmdlogger.New(stdout, stderr)

	slog.SetDefault(slog.New(logger))

	// Allow multiple arguments to be defined by github actions by splitting the last argument
	// by new lines.
	args = splitLastArg(args)

	cli.VersionPrinter = func(cmd *cli.Command) {
		slog.Info("osv-scanner version: " + cmd.Version)
		slog.Info("commit: " + commit)
		slog.Info("built at: " + date)
	}

	app := &cli.Command{
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
			&cli.BoolFlag{
				Name:        "fail-on-vuln",
				Usage:       "whether to return 1 when vulnerabilities are found",
				DefaultText: "true",
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			var termWidth int
			var err error
			if stdoutAsFile, ok := stdout.(*os.File); ok {
				termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
				if err != nil { // If output is not a terminal,
					termWidth = 0
				}
			}

			oldPath := cmd.String("old")
			newPath := cmd.String("new")

			oldVulns := models.VulnerabilityResults{}
			if oldPath != "" {
				oldVulns, err = ci.LoadVulnResults(oldPath)
				if err != nil {
					slog.Warn(fmt.Sprintf("failed to open old results at %s: %v - likely because target branch has no lockfiles.", oldPath, err))
					// Do not return, assume there is no oldVulns (which will display all new vulns).
					oldVulns = models.VulnerabilityResults{}
				}
			}

			newVulns, err := ci.LoadVulnResults(newPath)
			if err != nil {
				slog.Warn(fmt.Sprintf("failed to open new results at %s: %v - likely because previous step failed.", newPath, err))
				newVulns = models.VulnerabilityResults{}
				// Do not return a non zero error code.
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

			if errPrint := reporter.PrintResult(&diffVulns, "table", stdout, termWidth); errPrint != nil {
				return fmt.Errorf("failed to write output: %w", errPrint)
			}

			if cmd.Bool("gh-annotations") {
				if errPrint := reporter.PrintResult(&diffVulns, "gh-annotations", stderr, termWidth); errPrint != nil {
					return fmt.Errorf("failed to write output: %w", errPrint)
				}
			}

			outputPath := cmd.String("output")
			if outputPath != "" {
				var err error
				stdout, err = os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				termWidth = 0

				if errPrint := reporter.PrintResult(&diffVulns, "sarif", stdout, termWidth); errPrint != nil {
					return fmt.Errorf("failed to write output: %w", errPrint)
				}
			}

			// Default to true, only false when explicitly set to false
			failOnVuln := !cmd.IsSet("fail-on-vuln") || cmd.Bool("fail-on-vuln")

			// Check if any is *not* called
			anyIsCalled := false
			for _, vuln := range diffVulns.Flatten() {
				if vuln.GroupInfo.IsCalled() {
					anyIsCalled = true
					break
				}
			}

			// if vulnerability exists it should return error
			if len(diffVulns.Results) > 0 && failOnVuln && anyIsCalled {
				return osvscanner.ErrVulnerabilitiesFound
			}

			return nil
		},
	}

	if err := app.Run(context.Background(), args); err != nil {
		if errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
			return 1
		}

		if errors.Is(err, osvscanner.ErrNoPackagesFound) {
			slog.Error("No package sources found, --help for usage information.")
			return 128
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

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}
