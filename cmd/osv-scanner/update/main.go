package update

import (
	"errors"
	"fmt"
	"io"
	"os"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/v2/internal/depsdev"
	"github.com/google/osv-scanner/v2/internal/remediation/suggest"
	"github.com/google/osv-scanner/v2/internal/remediation/upgrade"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/google/osv-scanner/v2/internal/resolution/depfile"
	"github.com/google/osv-scanner/v2/internal/resolution/manifest"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/reporter"
	"github.com/urfave/cli/v2"
)

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
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
				Action: func(_ *cli.Context, s string) error {
					if s != "deps.dev" && s != "native" {
						return fmt.Errorf("unsupported data-source \"%s\" - must be one of: deps.dev, native", s)
					}

					return nil
				},
			},
		},
		Action: func(ctx *cli.Context) error {
			var err error
			*r, err = action(ctx, stdout, stderr)

			return err
		},
	}
}

type updateOptions struct {
	Manifest      string
	IgnoreDev     bool
	UpgradeConfig upgrade.Config // Allowed upgrade levels per package.

	Client     client.DependencyClient
	ManifestRW manifest.ReadWriter
}

func action(ctx *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	r := reporter.NewTableReporter(stdout, stderr, reporter.InfoLevel, false, 0)

	options := updateOptions{
		Manifest:      ctx.String("manifest"),
		IgnoreDev:     ctx.Bool("ignore-dev"),
		UpgradeConfig: upgrade.ParseUpgradeConfig(ctx.StringSlice("upgrade-config"), r),
	}

	if _, err := os.Stat(options.Manifest); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("file not found: %s", options.Manifest)
	} else if err != nil {
		return nil, err
	}

	system := resolve.UnknownSystem
	if options.Manifest != "" {
		rw, err := manifest.GetReadWriter(options.Manifest, ctx.String("maven-registry"))
		if err != nil {
			return nil, err
		}
		options.ManifestRW = rw
		system = rw.System()
	}

	var err error
	switch ctx.String("data-source") {
	case "deps.dev":
		options.Client, err = client.NewDepsDevClient(depsdev.DepsdevAPI, "osv-scanner_update/"+version.OSVVersion)
		if err != nil {
			return nil, err
		}
	case "native":
		switch system {
		case resolve.Maven:
			options.Client, err = client.NewMavenRegistryClient(ctx.String("maven-registry"))
			if err != nil {
				return nil, err
			}
		case resolve.NPM, resolve.UnknownSystem:
			fallthrough
		default:
			return nil, fmt.Errorf("native data-source currently unsupported for %s ecosystem", system.String())
		}
	}

	df, err := depfile.OpenLocalDepFile(options.Manifest)
	if err != nil {
		return nil, err
	}
	mf, err := options.ManifestRW.Read(df)
	df.Close() // Close the dep file and we may re-open it for writing
	if err != nil {
		return nil, err
	}

	suggester, err := suggest.GetSuggester(mf.System())
	if err != nil {
		return nil, err
	}
	patch, err := suggester.Suggest(ctx.Context, options.Client, mf, suggest.Options{
		IgnoreDev:     options.IgnoreDev,
		UpgradeConfig: options.UpgradeConfig,
	})
	if err != nil {
		return nil, err
	}

	return r, manifest.Overwrite(options.ManifestRW, options.Manifest, patch)
}
