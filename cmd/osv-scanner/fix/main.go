package fix

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/remediation/upgrade"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/lockfile"
	"github.com/google/osv-scanner/internal/resolution/manifest"
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
	remediation.Options
	Client     client.ResolutionClient
	Manifest   string
	ManifestRW manifest.ReadWriter
	Lockfile   string
	LockfileRW lockfile.ReadWriter
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
				Action: func(_ *cli.Context, s string) error {
					if s != "deps.dev" && s != "native" {
						return fmt.Errorf("unsupported data-source \"%s\" - must be one of: deps.dev, native", s)
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:  "maven-registry",
				Usage: "URL of the default Maven registry to fetch metadata",
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
				Usage:    "remediation approach to use; value can be: in-place, relock, override",
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
					case "override":
						if !ctx.IsSet("manifest") {
							return errors.New("override strategy requires manifest file")
						}
					default:
						return fmt.Errorf("unsupported strategy \"%s\" - must be one of: in-place, relock, override", s)
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

			&cli.StringSliceFlag{
				Category:    upgradeCategory,
				Name:        "upgrade-config",
				Usage:       "the allowed package upgrades, in the format `[package-name:]level`. If package-name is omitted, level is applied to all packages. level must be one of (major, minor, patch, none).",
				DefaultText: "major",
			},
			&cli.BoolFlag{
				Category: upgradeCategory,
				Name:     "disallow-major-upgrades",
				Usage:    "disallow major version changes to dependencies",
				Hidden:   true,
			},
			&cli.StringSliceFlag{
				Category: upgradeCategory,
				Name:     "disallow-package-upgrades",
				Usage:    "list of packages to disallow version changes",
				Hidden:   true,
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
			&cli.BoolFlag{
				Category: vulnCategory,
				Name:     "maven-fix-management",
				Usage:    "(pom.xml) also remediate vulnerabilities in dependencyManagement packages that do not appear in the resolved dependency graph",
			},
			// Offline database flags, copied from osv-scanner scan
			&cli.BoolFlag{
				Name:    "experimental-offline-vulnerabilities",
				Aliases: []string{"experimental-offline"},
				Usage:   "checks for vulnerabilities using local databases that are already cached",
			},
			&cli.BoolFlag{
				Name:  "experimental-download-offline-databases",
				Usage: "downloads vulnerability databases for offline comparison",
			},
			&cli.StringFlag{
				Name:   "experimental-local-db-path",
				Usage:  "sets the path that local databases should be stored",
				Hidden: true,
			},
		},
		Action: func(ctx *cli.Context) error {
			var err error
			*r, err = action(ctx, stdout, stderr)

			return err
		},
	}
}

func parseUpgradeConfig(ctx *cli.Context, r reporter.Reporter) upgrade.Config {
	config := upgrade.NewConfig()

	if ctx.IsSet("disallow-major-upgrades") {
		r.Warnf("WARNING: `--disallow-major-upgrades` flag is deprecated, use `--upgrade-config minor` instead\n")
		if ctx.Bool("disallow-major-upgrades") {
			config.SetDefault(upgrade.Minor)
		} else {
			config.SetDefault(upgrade.Major)
		}
	}
	if ctx.IsSet("disallow-package-upgrades") {
		r.Warnf("WARNING: `--disallow-package-upgrades` flag is deprecated, use `--upgrade-config PKG:none` instead\n")
		for _, pkg := range ctx.StringSlice("disallow-package-upgrades") {
			config.Set(pkg, upgrade.None)
		}
	}

	for _, spec := range ctx.StringSlice("upgrade-config") {
		idx := strings.LastIndex(spec, ":")
		if idx == 0 {
			r.Warnf("WARNING: `--upgrade-config %s` - skipping empty package name\n", spec)
			continue
		}
		pkg := ""
		levelStr := spec
		if idx > 0 {
			pkg = spec[:idx]
			levelStr = spec[idx+1:]
		}
		var level upgrade.Level
		switch levelStr {
		case "major":
			level = upgrade.Major
		case "minor":
			level = upgrade.Minor
		case "patch":
			level = upgrade.Patch
		case "none":
			level = upgrade.None
		default:
			r.Warnf("WARNING: `--upgrade-config %s` - invalid level string '%s'\n", spec, levelStr)
			continue
		}
		if config.Set(pkg, level) { // returns true if was previously set
			r.Warnf("WARNING: `--upgrade-config %s` - config for package specified multiple times\n", spec)
		}
	}

	return config
}

func action(ctx *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	if !ctx.IsSet("manifest") && !ctx.IsSet("lockfile") {
		return nil, errors.New("manifest or lockfile is required")
	}

	// TODO: This isn't what the reporter is designed for.
	// Only using r.Infof()/r.Warnf()/r.Errorf() to print to stdout/stderr.
	r := reporter.NewTableReporter(stdout, stderr, reporter.InfoLevel, false, 0)

	opts := osvFixOptions{
		Options: remediation.Options{
			ResolveOpts: resolution.ResolveOpts{
				MavenManagement: ctx.Bool("maven-fix-management"),
			},
			IgnoreVulns:   ctx.StringSlice("ignore-vulns"),
			ExplicitVulns: ctx.StringSlice("vulns"),
			DevDeps:       !ctx.Bool("ignore-dev"),
			MinSeverity:   ctx.Float64("min-severity"),
			MaxDepth:      ctx.Int("max-depth"),
			UpgradeConfig: parseUpgradeConfig(ctx, r),
		},
		Manifest:  ctx.String("manifest"),
		Lockfile:  ctx.String("lockfile"),
		RelockCmd: ctx.String("relock-cmd"),
	}

	system := resolve.UnknownSystem
	if opts.Lockfile != "" {
		rw, err := lockfile.GetReadWriter(opts.Lockfile)
		if err != nil {
			return nil, err
		}
		opts.LockfileRW = rw
		system = rw.System()
	}

	if opts.Manifest != "" {
		rw, err := manifest.GetReadWriter(opts.Manifest, ctx.String("maven-registry"))
		if err != nil {
			return nil, err
		}
		opts.ManifestRW = rw
		// Prefer the manifest's system over the lockfile's.
		// TODO: make sure they match
		system = rw.System()
	}

	switch ctx.String("data-source") {
	case "deps.dev":
		cl, err := client.NewDepsDevClient(depsdev.DepsdevAPI)
		if err != nil {
			return nil, err
		}
		opts.Client.DependencyClient = cl
	case "native":
		switch system {
		case resolve.NPM:
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
		case resolve.Maven:
			cl, err := client.NewMavenRegistryClient(ctx.String("maven-registry"))
			if err != nil {
				return nil, err
			}
			opts.Client.DependencyClient = cl
		case resolve.UnknownSystem:
			fallthrough
		default:
			return nil, fmt.Errorf("native data-source currently unsupported for %s ecosystem", system.String())
		}
	}

	if ctx.Bool("experimental-offline-vulnerabilities") {
		var err error
		opts.Client.VulnerabilityClient, err = client.NewOSVOfflineClient(
			r,
			system,
			ctx.Bool("experimental-download-offline-databases"),
			ctx.String("experimental-local-db-path"))
		if err != nil {
			return nil, err
		}
	} else {
		opts.Client.VulnerabilityClient = client.NewOSVClient()
	}

	if !ctx.Bool("non-interactive") {
		return nil, interactiveMode(ctx.Context, opts)
	}

	maxUpgrades := ctx.Int("apply-top")

	strategy := ctx.String("strategy")

	if !ctx.IsSet("strategy") {
		// Choose a default strategy based on the manifest/lockfile provided.
		switch {
		case remediation.SupportsRelax(opts.ManifestRW):
			strategy = "relock"
		case remediation.SupportsOverride(opts.ManifestRW):
			strategy = "override"
		case remediation.SupportsInPlace(opts.LockfileRW):
			strategy = "in-place"
		default:
			return nil, errors.New("no supported remediation strategies for manifest/lockfile")
		}
	}

	switch strategy {
	case "relock":
		return r, autoRelock(ctx.Context, r, opts, maxUpgrades)
	case "in-place":
		return r, autoInPlace(ctx.Context, r, opts, maxUpgrades)
	case "override":
		return r, autoOverride(ctx.Context, r, opts, maxUpgrades)
	default:
		// The strategy flag should already be validated by this point.
		panic(fmt.Sprintf("non-interactive mode attempted to run with unhandled strategy: \"%s\"", ctx.String("strategy")))
	}
}
