package docker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scanner/cmd/osv-scanner/scan/helper"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"golang.org/x/term"

	"github.com/urfave/cli/v2"
)

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "docker",
		Usage:       "detects vulnerabilities in a Docker image's dependencies using the OSV database.",
		Description: "detects vulnerabilities in a Docker image's dependencies using the OSV database.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "sets the output format; value can be: " + strings.Join(reporter.Format(), ", "),
				Value:   "table",
				Action: func(_ *cli.Context, s string) error {
					if slices.Contains(reporter.Format(), s) {
						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
				},
			},
			&cli.BoolFlag{
				Name:  "serve",
				Usage: "output as HTML result and serve it locally",
			},
			&cli.StringFlag{
				Name:      "output",
				Usage:     "saves the result to the given file path",
				TakesFile: true,
			},
			&cli.StringFlag{
				Name:      "config",
				Usage:     "set/override config file",
				TakesFile: true,
			},
			&cli.StringFlag{
				Name:  "verbosity",
				Usage: "specify the level of information that should be provided during runtime; value can be: " + strings.Join(reporter.VerbosityLevels(), ", "),
				Value: "info",
			},
		},
		ArgsUsage: "[docker image]",
		Action: func(c *cli.Context) error {
			var err error
			*r, err = action(c, stdout, stderr)

			return err
		},
	}
}

func action(context *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	format := context.String("format")

	outputPath := context.String("output")
	serve := context.Bool("serve")
	if serve {
		format = "html"
		if outputPath == "" {
			// Create a temporary directory
			tmpDir, err := os.MkdirTemp("", "osv-scanner-result")
			if err != nil {
				return nil, fmt.Errorf("failed creating temporary directory: %w\n"+
					"Please use `--output result.html` to specify the output path", err)
			}

			// Remove the created temporary directory after
			defer os.RemoveAll(tmpDir)
			outputPath = filepath.Join(tmpDir, "index.html")
		}
	}

	termWidth := 0
	var err error
	if outputPath != "" { // Output is definitely a file
		stdout, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
	} else { // Output might be a terminal
		if stdoutAsFile, ok := stdout.(*os.File); ok {
			termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
			if err != nil { // If output is not a terminal,
				termWidth = 0
			}
		}
	}

	verbosityLevel, err := reporter.ParseVerbosityLevel(context.String("verbosity"))
	if err != nil {
		return nil, err
	}
	r, err := reporter.New(format, stdout, stderr, verbosityLevel, termWidth)
	if err != nil {
		return r, err
	}

	scannerAction := osvscanner.ScannerActions{
		Image:              context.Args().First(),
		ConfigOverridePath: context.String("config"),
	}

	var vulnResult models.VulnerabilityResults
	vulnResult, err = osvscanner.DoContainerScan(scannerAction, r)

	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return r, err
	}

	if errPrint := r.PrintResult(&vulnResult); errPrint != nil {
		return r, fmt.Errorf("failed to write output: %w", errPrint)
	}

	// Auto-open outputted HTML file for users.
	if outputPath != "" {
		if serve {
			helper.ServeHTML(r, outputPath)
		} else if format == "html" {
			helper.OpenHTML(r, outputPath)
		}
	}

	// This may be nil.
	return r, err
}
