// Package image implements the `image` subcommand of the `scan` command.
package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

func Command(stdout, stderr io.Writer, clientFactories scalibrconfig.ClientFactories) *cli.Command {
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
			return action(ctx, cmd, stdout, stderr, clientFactories)
		},
	}
}

func action(ctx context.Context, cmd *cli.Command, stdout, stderr io.Writer, clientFactories scalibrconfig.ClientFactories) error {
	if cmd.Args().Len() == 0 {
		return errors.New("please provide an image name or see the help document")
	}

	isImageArchive := cmd.Bool("archive")
	image := cmd.Args().First()
	if !isImageArchive && !strings.Contains(image, ":") {
		return fmt.Errorf("%q is not a tagged image name", image)
	}

	return helper.Action(
		ctx, cmd,
		stdout, stderr,
		clientFactories,
		func(actions *osvscanner.ScannerActions) {
			actions.RequestUserAgent = "osv-scanner_scan-image/" + version.OSVVersion

			actions.Image = cmd.Args().First()
			actions.IsImageArchive = cmd.Bool("archive")
		},
		osvscanner.DoContainerScan,
	)
}
