package update

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/osv-scanner/internal/remediation/suggest"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/pkg/depsdev"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
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
			&cli.StringSliceFlag{
				Name:  "disallow-package-upgrades",
				Usage: "list of packages that disallow updates",
			},
			&cli.StringSliceFlag{
				Name:  "disallow-major-upgrades",
				Usage: "list of packages that disallow major updates",
			},
			&cli.BoolFlag{
				Name:  "ignore-dev",
				Usage: "whether to ignore development dependencies for updates",
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
	Manifest   string
	NoUpdates  []string
	AvoidMajor []string
	IgnoreDev  bool

	Client     client.ResolutionClient
	ManifestRW manifest.ManifestIO
}

func action(ctx *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	options := updateOptions{
		Manifest:   ctx.String("manifest"),
		NoUpdates:  ctx.StringSlice("disallow-package-upgrades"),
		AvoidMajor: ctx.StringSlice("disallow-major-upgrades"),
		IgnoreDev:  ctx.Bool("ignore-dev"),
	}
	if _, err := os.Stat(options.Manifest); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("file not found: %s", options.Manifest)
	} else if err != nil {
		return nil, err
	}

	var err error
	options.Client.DependencyClient, err = client.NewDepsDevClient(depsdev.DepsdevAPI)
	if err != nil {
		return nil, err
	}
	options.ManifestRW, err = manifest.GetManifestIO(options.Manifest)
	if err != nil {
		return nil, err
	}

	df, err := lockfile.OpenLocalDepFile(options.Manifest)
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
		IgnoreDev:  options.IgnoreDev,
		NoUpdates:  options.NoUpdates,
		AvoidMajor: options.AvoidMajor,
	})
	if err != nil {
		return nil, err
	}

	return reporter.NewTableReporter(stdout, stderr, reporter.InfoLevel, false, 0), manifest.Overwrite(options.ManifestRW, options.Manifest, patch)
}
