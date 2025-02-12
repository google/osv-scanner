package image

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/google/osv-scanner/v2/pkg/reporter"

	"github.com/urfave/cli/v2"
)

var imageScanFlags = []cli.Flag{
	&cli.BoolFlag{
		Name:  "archive",
		Usage: "input a local archive image (e.g. a tar file)",
	},
}

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "image",
		Usage:       "detects vulnerabilities in a container image's dependencies, pulling the image if it's not found locally",
		Description: "detects vulnerabilities in a container image's dependencies, pulling the image if it's not found locally",
		Flags:       append(imageScanFlags, helper.GetScanGlobalFlags()...),
		ArgsUsage:   "[image imageName]",
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

	r, err := helper.GetReporter(context, stdout, stderr, outputPath, format)
	if err != nil {
		return nil, err
	}

	scanLicensesAllowlist, err := helper.GetScanLicensesAllowlist(context)
	if err != nil {
		return nil, err
	}

	if context.Args().Len() == 0 {
		return r, errors.New("please provide an image name or see the help document")
	}
	scannerAction := osvscanner.ScannerActions{
		Image:                      context.Args().First(),
		ConfigOverridePath:         context.String("config"),
		IsImageArchive:             context.Bool("archive"),
		IncludeGitRoot:             context.Bool("include-git-root"),
		ExperimentalScannerActions: helper.GetExperimentalScannerActions(context, scanLicensesAllowlist),
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
			helper.ServeHTML(outputPath)
		} else if format == "html" {
			helper.OpenHTML(outputPath)
		}
	}

	// This may be nil.
	return r, err
}
