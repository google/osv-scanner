// Package image implements the `image` subcommand of the `scan` command.
package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

func Command(stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "image",
		Usage:       "detects vulnerabilities in a container image's dependencies, pulling the image if it's not found locally",
		Description: "detects vulnerabilities in a container image's dependencies, pulling the image if it's not found locally",
		Flags: append([]cli.Flag{
			&cli.BoolFlag{
				Name:  "archive",
				Usage: "input a local archive image (e.g. a tar file)",
			},
		}, helper.BuildCommonScanFlags([]string{"artifact"})...),
		ArgsUsage: "[image imageNameWithTag]",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return action(ctx, cmd, stdout, stderr)
		},
	}
}

func action(_ context.Context, cmd *cli.Command, stdout, stderr io.Writer) error {
	if cmd.Args().Len() == 0 {
		return errors.New("please provide an image name or see the help document")
	}

	isImageArchive := cmd.Bool("archive")
	image := cmd.Args().First()
	if !isImageArchive && !strings.Contains(image, ":") {
		return fmt.Errorf("%q is not a tagged image name", image)
	}

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

	scannerAction := helper.GetCommonScannerActions(cmd, scanLicensesAllowlist)

	scannerAction.Image = cmd.Args().First()
	scannerAction.IsImageArchive = cmd.Bool("archive")
	scannerAction.ExperimentalScannerActions = helper.GetExperimentalScannerActions(cmd)

	var vulnResult models.VulnerabilityResults
	//nolint:contextcheck // passing the context in would be a breaking change
	vulnResult, err = osvscanner.DoContainerScan(scannerAction)

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
