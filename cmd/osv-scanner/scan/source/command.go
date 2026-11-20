// Package source implements the `source` subcommand of the `scan` command.
package source

import (
	"context"
	"fmt"
	"io"

	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

func Command(stdout, stderr io.Writer, clientFactories scalibrconfig.ClientFactories) *cli.Command {
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
			&cli.StringSliceFlag{
				Name:  "experimental-exclude",
				Usage: "[DEPRECATED] (use \"--x-exclude\" instead) exclude directory paths during scanning; use g:pattern for glob, r:pattern for regex, or just dirname for exact match (can be repeated)",
				Action: func(_ context.Context, _ *cli.Command, _ []string) error {
					cmdlogger.Warnf("Warning: --experimental-exclude has been deprecated in favor of --x-exclude")

					return nil
				},
			},
			&cli.StringSliceFlag{
				Name:  "x-exclude",
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
			return action(ctx, cmd, stdout, stderr, clientFactories)
		},
	}
}

func action(ctx context.Context, cmd *cli.Command, stdout, stderr io.Writer, clientFactories scalibrconfig.ClientFactories) error {
	return helper.Action(
		ctx, cmd,
		stdout, stderr,
		clientFactories,
		func(actions *osvscanner.ScannerActions) {
			actions.RequestUserAgent = "osv-scanner_scan-source/" + version.OSVVersion

			actions.LockfilePaths = cmd.StringSlice("lockfile")
			//nolint:staticcheck // ignore our own deprecated field
			actions.SBOMPaths = cmd.StringSlice("sbom")
			actions.Recursive = cmd.Bool("recursive")
			actions.NoIgnore = cmd.Bool("no-ignore")
			actions.DirectoryPaths = cmd.Args().Slice()

			actions.ExcludePatterns = cmd.StringSlice(helper.FallbackToDeprecatedName(cmd, "x-exclude", "experimental-exclude"))
			actions.TransitiveScanning = osvscanner.TransitiveScanningActions{
				Disabled:         cmd.Bool("no-resolve"),
				NativeDataSource: cmd.String("data-source") == "native",
				MavenRegistry:    cmd.String("maven-registry"),
			}
		},
		osvscanner.DoScan,
	)
}
