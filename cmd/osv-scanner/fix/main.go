package fix

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/lockfile"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/pkg/depsdev"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

const (
	vulnCategory     = "Vulnerability Selection Options:"
	upgradeCategory  = "Dependency Upgrade Options:"
	autoModeCategory = "non-interactive options:" // intentionally lowercase to force it to sort after the other categories
)

type osvFixOptions struct {
	remediation.RemediationOptions
	Client     client.ResolutionClient
	Manifest   string
	ManifestRW manifest.ManifestIO
	Lockfile   string
	LockfileRW lockfile.LockfileIO
	RelockCmd  string
}

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "fix",
		Usage:       "[EXPERIMENTAL] scans a manifest and/or lockfile for vulnerabilities and suggests changes for remediating them",
		Description: "[EXPERIMENTAL] scans a manifest and/or lockfile for vulnerabilities and suggests changes for remediating them",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      "manifest",
				Aliases:   []string{"M"},
				Usage:     "manifest file to remediate vulnerabilities in",
				TakesFile: true,
			},
			&cli.StringFlag{
				Name:      "lockfile",
				Aliases:   []string{"L"},
				Usage:     "lockfile to remediate vulnerabilities in",
				TakesFile: true,
			},
			&cli.StringFlag{
				Name:  "data-source",
				Usage: "source to fetch package information from; value can be: deps.dev, native",
				Value: "deps.dev",
				Action: func(ctx *cli.Context, s string) error {
					if s != "deps.dev" && s != "native" {
						return fmt.Errorf("unsupported data-source \"%s\" - must be one of: deps.dev, native", s)
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:  "relock-cmd",
				Usage: "command to run to regenerate lockfile on disk after changing the manifest",
			},

			&cli.BoolFlag{
				Name:  "non-interactive",
				Usage: "run in the non-interactive mode",
				Value: !term.IsTerminal(int(os.Stdin.Fd())), // Default to non-interactive if not being run in a terminal
			},
			&cli.StringFlag{
				Category: autoModeCategory,
				Name:     "strategy",
				Usage:    "remediation approach to use; value can be: in-place, relock",
				Value:    "relock",
				Action: func(ctx *cli.Context, s string) error {
					if !ctx.Bool("non-interactive") {
						// This flag isn't used in interactive mode
						return nil
					}
					switch s {
					case "in-place":
						if !ctx.IsSet("lockfile") {
							return errors.New("in-place strategy requires lockfile")
						}
					case "relock":
						if !ctx.IsSet("manifest") {
							return errors.New("relock strategy requires manifest file")
						}
					default:
						return fmt.Errorf("unsupported strategy \"%s\" - must be one of: in-place, relock", s)
					}

					return nil
				},
			},
			&cli.IntFlag{
				Category: autoModeCategory,
				Name:     "apply-top",
				Usage:    "apply the top N patches",
				Value:    -1,
			},

			&cli.BoolFlag{
				// TODO: allow for finer control e.g. specific packages, major/minor/patch
				Category: upgradeCategory,
				Name:     "disallow-major-upgrades",
				Usage:    "disallow major version changes to dependencies",
			},
			&cli.StringSliceFlag{
				Category: upgradeCategory,
				Name:     "disallow-package-upgrades",
				Usage:    "list of packages to disallow version changes",
			},

			&cli.IntFlag{
				Category: vulnCategory,
				Name:     "max-depth",
				Usage:    "maximum dependency depth of vulnerabilities to consider",
				Value:    -1,
			},
			&cli.Float64Flag{
				Category:    vulnCategory,
				Name:        "min-severity",
				Usage:       "minimum CVSS score of vulnerabilities to consider",
				Value:       0,
				DefaultText: "0.0",
			},
			&cli.StringSliceFlag{
				Category: vulnCategory,
				Name:     "vulns",
				Usage:    "explicit list of vulnerability IDs to consider",
			},
			&cli.StringSliceFlag{
				Category: vulnCategory,
				Name:     "ignore-vulns",
				Usage:    "list of vulnerability IDs to ignore",
			},
			&cli.BoolFlag{
				Category: vulnCategory,
				Name:     "ignore-dev",
				Usage:    "ignore vulnerabilities affecting only development dependencies",
			},
		},
		Action: func(ctx *cli.Context) error {
			var err error
			*r, err = action(ctx, stdout, stderr)

			return err
		},
	}
}

func action(ctx *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	// The Action on strategy isn't run when using the default values. Check if the manifest is set.
	if ctx.Bool("non-interactive") && ctx.String("strategy") == "relock" && !ctx.IsSet("manifest") {
		return nil, errors.New("relock strategy requires manifest file")
	}

	if !ctx.IsSet("manifest") && !ctx.IsSet("lockfile") {
		return nil, errors.New("manifest or lockfile is required")
	}

	opts := osvFixOptions{
		RemediationOptions: remediation.RemediationOptions{
			IgnoreVulns:   ctx.StringSlice("ignore-vulns"),
			ExplicitVulns: ctx.StringSlice("vulns"),
			DevDeps:       !ctx.Bool("ignore-dev"),
			MinSeverity:   ctx.Float64("min-severity"),
			MaxDepth:      ctx.Int("max-depth"),
			AvoidPkgs:     ctx.StringSlice("disallow-package-upgrades"),
			AllowMajor:    !ctx.Bool("disallow-major-upgrades"),
		},
		Manifest:  ctx.String("manifest"),
		Lockfile:  ctx.String("lockfile"),
		RelockCmd: ctx.String("relock-cmd"),
		Client: client.ResolutionClient{
			VulnerabilityClient: client.NewOSVClient(),
		},
	}

	switch ctx.String("data-source") {
	case "deps.dev":
		cl, err := client.NewDepsDevClient(depsdev.DepsdevAPI)
		if err != nil {
			return nil, err
		}
		opts.Client.DependencyClient = cl
	case "native":
		// TODO: determine ecosystem & client from manifest/lockfile
		var workDir string
		// Prefer to use the manifest's directory if available.
		if opts.Manifest != "" {
			workDir = filepath.Dir(opts.Manifest)
		} else {
			workDir = filepath.Dir(opts.Lockfile)
		}
		cl, err := client.NewNpmRegistryClient(workDir)
		if err != nil {
			return nil, err
		}
		opts.Client.DependencyClient = cl
	}

	if opts.Manifest != "" {
		rw, err := manifest.GetManifestIO(opts.Manifest)
		if err != nil {
			return nil, err
		}
		opts.ManifestRW = rw
	}

	if opts.Lockfile != "" {
		rw, err := lockfile.GetLockfileIO(opts.Lockfile)
		if err != nil {
			return nil, err
		}
		opts.LockfileRW = rw
	}

	if !ctx.Bool("non-interactive") {
		return nil, interactiveMode(ctx.Context, opts)
	}

	// TODO: This isn't what the reporter is designed for.
	// Only using r.Infof() and r.Errorf() to print to stdout & stderr respectively.
	r := reporter.NewTableReporter(stdout, stderr, reporter.InfoLevel, false, 0)
	maxUpgrades := ctx.Int("apply-top")

	switch ctx.String("strategy") {
	case "relock":
		return r, autoRelock(ctx.Context, r, opts, maxUpgrades)
	case "in-place":
		return r, autoInPlace(ctx.Context, r, opts, maxUpgrades)
	default:
		// The strategy flag should already be validated by this point.
		panic(fmt.Sprintf("non-interactive mode attempted to run with unhandled strategy: \"%s\"", ctx.String("strategy")))
	}
}
