// Package update implements the `update` command for osv-scanner.
package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/depsdev"
	"github.com/google/osv-scalibr/guidedremediation"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/urfave/cli/v3"
)

func Command(_, _ io.Writer, _ *http.Client) *cli.Command {
	return &cli.Command{
		Hidden: true,
		Name:   "update",
		Usage:  "[EXPERIMENTAL] scans a manifest file then updates dependencies",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      "manifest",
				Aliases:   []string{"M"},
				Usage:     "path to manifest file (required)",
				TakesFile: true,
				Required:  true,
			},
			&cli.BoolFlag{
				Name:  "ignore-dev",
				Usage: "whether to ignore development dependencies for updates",
			},
			&cli.StringSliceFlag{
				Name:        "upgrade-config",
				Usage:       "the allowed package upgrades, in the format `[package-name:]level`. If package-name is omitted, level is applied to all packages. level must be one of (major, minor, patch, none).",
				DefaultText: "major",
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
		},
		Action: action,
	}
}

func action(ctx context.Context, cmd *cli.Command) error {
	cmdlogger.Warnf("Version updates (the update command) can be risky when run on untrusted projects. It may trigger the package manager to execute scripts or follow external registries specified in the project. Please ensure you trust the source code and artifacts before proceeding.")

	opts := options.UpdateOptions{
		Manifest:      cmd.String("manifest"),
		IgnoreDev:     cmd.Bool("ignore-dev"),
		UpgradeConfig: upgrade.NewConfigFromStrings(cmd.StringSlice("upgrade-config")),
	}

	if _, err := os.Stat(opts.Manifest); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("file not found: %s", opts.Manifest)
	} else if err != nil {
		return err
	}

	// MavenClient is required for Maven projects
	mc, err := datasource.NewMavenRegistryAPIClient(ctx, datasource.MavenRegistry{
		URL:             cmd.String("maven-registry"),
		ReleasesEnabled: true,
	}, "", false)
	if err != nil {
		return err
	}
	opts.MavenClient = mc

	userAgent := "osv-scanner_update/" + version.OSVVersion
	switch cmd.String("data-source") {
	case "deps.dev":
		cl, err := resolution.NewDepsDevClient(depsdev.DepsdevAPI, userAgent)
		if err != nil {
			return err
		}
		opts.ResolveClient = cl
	case "native":
		cl, err := resolution.NewCombinedNativeClient(resolution.CombinedNativeClientOptions{
			ProjectDir:  filepath.Dir(opts.Manifest),
			MavenClient: mc,
		})
		if err != nil {
			return err
		}
		opts.ResolveClient = cl
	}

	_, err = guidedremediation.Update(opts)

	return err
}
