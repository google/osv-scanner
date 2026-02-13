// Package source implements the `source` subcommand of the `scan` command.
package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

func Command(stdout, stderr io.Writer, client *http.Client) *cli.Command {
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
			&cli.StringSliceFlag{
				Name:  "experimental-exclude",
				Usage: "exclude directory paths during scanning; use g:pattern for glob, r:pattern for regex, or just dirname for exact match (can be repeated)",
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
			return action(ctx, cmd, stdout, stderr, client)
		},
	}
}

func action(_ context.Context, cmd *cli.Command, stdout, stderr io.Writer, client *http.Client) error {
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

	experimentalScannerActions := helper.GetExperimentalScannerActions(cmd, client)
	experimentalScannerActions.RequestUserAgent = "osv-scanner_scan-source/" + version.OSVVersion
	experimentalScannerActions.ExcludePatterns = cmd.StringSlice("experimental-exclude")
	// Add `source` specific experimental configs
	experimentalScannerActions.TransitiveScanning = osvscanner.TransitiveScanningActions{
		Disabled:         cmd.Bool("no-resolve"),
		NativeDataSource: cmd.String("data-source") == "native",
		MavenRegistry:    cmd.String("maven-registry"),
	}

	scannerAction := helper.GetCommonScannerActions(cmd, scanLicensesAllowlist)

	scannerAction.LockfilePaths = cmd.StringSlice("lockfile")
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
