// Package source implements the `source` subcommand of the `scan` command.
package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

func Command(stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "source",
		Usage:       "scans a source project's dependencies for known vulnerabilities using the OSV database.",
		Description: "scans a source project's dependencies for known vulnerabilities using the OSV database.",
		Flags: append([]cli.Flag{
			&cli.StringSliceFlag{
				Name:      "lockfile",
				Aliases:   []string{"L"},
				Usage:     "scan package lockfile on this path",
				TakesFile: true,
			},
			&cli.StringSliceFlag{
				Name:    "sbom",
				Aliases: []string{"S"},
				Usage:   "[DEPRECATED] scan sbom file on this path, the sbom file name must follow the relevant spec",
				Action: func(_ context.Context, _ *cli.Command, _ []string) error {
					cmdlogger.Warnf("Warning: --sbom has been deprecated in favor of -L")

					return nil
				},
				TakesFile: true,
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "check subdirectories",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:  "no-ignore",
				Usage: "also scan files that would be ignored by .gitignore",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "include-git-root",
				Usage: "include scanning git root (non-submoduled) repositories",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "data-source",
				Usage: "source to fetch package information from; value can be: deps.dev, native",
				Value: "deps.dev",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if s != "deps.dev" && s != "native" {
						return fmt.Errorf("unsupported data-source \"%s\" - must be one of: deps.dev, native", s)
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:  "maven-registry",
				Usage: "URL of the default registry to fetch Maven metadata",
			},
		}, helper.BuildCommonScanFlags([]string{"lockfile", "sbom", "directory"})...),
		ArgsUsage: "[directory1 directory2...]",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return action(ctx, cmd, stdout, stderr)
		},
	}
}

func action(_ context.Context, cmd *cli.Command, stdout, stderr io.Writer) error {
	format := cmd.String("format")

	outputPath := cmd.String("output")
	serve := cmd.Bool("serve")
	if serve {
		format = "html"
		if outputPath == "" {
			// Create a temporary directory
			tmpDir, err := os.MkdirTemp("", "osv-scanner-result")
			if err != nil {
				return fmt.Errorf("failed creating temporary directory: %w\n"+
					"Please use `--output result.html` to specify the output path", err)
			}

			// Remove the created temporary directory after
			defer os.RemoveAll(tmpDir)
			outputPath = filepath.Join(tmpDir, "index.html")
		}
	}

	scanLicensesAllowlist, err := helper.GetScanLicensesAllowlist(cmd)
	if err != nil {
		return err
	}

	experimentalScannerActions := helper.GetExperimentalScannerActions(cmd)
	// Add `source` specific experimental configs
	experimentalScannerActions.TransitiveScanningActions = osvscanner.TransitiveScanningActions{
		Disabled:         cmd.Bool("no-resolve"),
		NativeDataSource: cmd.String("data-source") == "native",
		MavenRegistry:    cmd.String("maven-registry"),
	}

	scannerAction := helper.GetCommonScannerActions(cmd, scanLicensesAllowlist)

	scannerAction.LockfilePaths = cmd.StringSlice("lockfile")
	//nolint:staticcheck // ignore our own deprecated field
	scannerAction.SBOMPaths = cmd.StringSlice("sbom")
	scannerAction.Recursive = cmd.Bool("recursive")
	scannerAction.NoIgnore = cmd.Bool("no-ignore")
	scannerAction.DirectoryPaths = cmd.Args().Slice()
	scannerAction.ExperimentalScannerActions = experimentalScannerActions

	var vulnResult models.VulnerabilityResults
	//nolint:contextcheck // passing the context in would be a breaking change
	vulnResult, err = osvscanner.DoScan(scannerAction)

	if cmd.Bool("allow-no-lockfiles") && errors.Is(err, osvscanner.ErrNoPackagesFound) {
		cmdlogger.Warnf("No package sources found")
		err = nil
	}

	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return err
	}

	if errPrint := helper.PrintResult(stdout, stderr, outputPath, format, &vulnResult, scannerAction.ShowAllVulns); errPrint != nil {
		return fmt.Errorf("failed to write output: %w", errPrint)
	}

	// Auto-open outputted HTML file for users.
	if outputPath != "" {
		if serve {
			helper.ServeHTML(outputPath)
		} else if format == "html" {
			cmdlogger.Infof("HTML output available at: %s", outputPath)
		}
	}

	// This may be nil.
	return err
}
