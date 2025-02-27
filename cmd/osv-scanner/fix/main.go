package fix

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/osvmatcher"
	"github.com/google/osv-scanner/v2/internal/depsdev"
	"github.com/google/osv-scanner/v2/internal/imodels/ecosystem"
	"github.com/google/osv-scanner/v2/internal/osvdev"
	"github.com/google/osv-scanner/v2/internal/remediation"
	"github.com/google/osv-scanner/v2/internal/remediation/upgrade"
	"github.com/google/osv-scanner/v2/internal/resolution"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/google/osv-scanner/v2/internal/resolution/lockfile"
	"github.com/google/osv-scanner/v2/internal/resolution/manifest"
	"github.com/google/osv-scanner/v2/internal/resolution/util"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/reporter"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

type strategy string

const (
	strategyInPlace  strategy = "in-place"
	strategyRelax    strategy = "relax"
	strategyOverride strategy = "override"
)

var strategies = []string{string(strategyInPlace), string(strategyRelax), string(strategyOverride)}

const (
	vulnCategory     = "Vulnerability Selection Options:"
	upgradeCategory  = "Dependency Upgrade Options:"
	autoModeCategory = "non-interactive options:" // intentionally lowercase to force it to sort after the other categories
)

type osvFixOptions struct {
	remediation.Options
	Client      client.ResolutionClient
	Manifest    string
	ManifestRW  manifest.ReadWriter
	Lockfile    string
	LockfileRW  lockfile.ReadWriter
	NoIntroduce bool
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

			&cli.BoolFlag{
				Name:  "non-interactive",
				Usage: "run in the non-interactive mode",
				Value: !term.IsTerminal(int(os.Stdin.Fd())), // Default to non-interactive if not being run in a terminal
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "sets the non-interactive output format; value can be: text, json",
				Value:   "text",
				Action: func(_ *cli.Context, s string) error {
					if s == "text" || s == "json" {
						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: text, json", s)
				},
			},
			&cli.StringFlag{
				Category: autoModeCategory,
				Name:     "strategy",
				Usage:    "remediation approach to use; value can be: " + strings.Join(strategies, ", "),
				Action: func(ctx *cli.Context, s string) error {
					if !ctx.Bool("non-interactive") {
						// This flag isn't used in interactive mode
						return nil
					}
					switch strategy(s) {
					case strategyInPlace:
						if !ctx.IsSet("lockfile") {
							return fmt.Errorf("%s strategy requires lockfile", strategyInPlace)
						}
					case strategy("relock"): // renamed
						fallthrough
					case strategyRelax:
						if !ctx.IsSet("manifest") {
							return fmt.Errorf("%s strategy requires manifest file", strategyRelax)
						}
					case strategyOverride:
						if !ctx.IsSet("manifest") {
							return fmt.Errorf("%s strategy requires manifest file", strategyOverride)
						}
					default:
						return fmt.Errorf("unsupported strategy \"%s\" - must be one of: %s", s, strings.Join(strategies, ", "))
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
				Category: autoModeCategory,
				Name:     "no-introduce",
				Usage:    "exclude patches that would introduce new vulnerabilities",
			},

			&cli.StringSliceFlag{
				Category:    upgradeCategory,
				Name:        "upgrade-config",
				Usage:       "the allowed package upgrades, in the format `[package-name:]level`. If package-name is omitted, level is applied to all packages. level must be one of (major, minor, patch, none).",
				DefaultText: "major",
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
				Name:    "offline-vulnerabilities",
				Aliases: []string{"offline"},
				Usage:   "checks for vulnerabilities using local databases that are already cached",
			},
			&cli.BoolFlag{
				Name:  "download-offline-databases",
				Usage: "downloads vulnerability databases for offline comparison",
			},
			&cli.StringFlag{
				Name:   "local-db-path",
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

func action(ctx *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	if !ctx.IsSet("manifest") && !ctx.IsSet("lockfile") {
		return nil, errors.New("manifest or lockfile is required")
	}

	r := new(outputReporter)
	switch ctx.String("format") {
	case "json":
		r.Stdout = stderr
		r.Stderr = stderr
		r.OutputResult = func(fo fixOutput) error { return outputJSON(stdout, fo) }
	case "text":
		fallthrough
	default:
		r.Stdout = stdout
		r.Stderr = stderr
		r.OutputResult = func(fo fixOutput) error { return outputText(stdout, fo) }
	}

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
			UpgradeConfig: upgrade.ParseUpgradeConfig(ctx.StringSlice("upgrade-config"), r),
		},
		Manifest:    ctx.String("manifest"),
		Lockfile:    ctx.String("lockfile"),
		NoIntroduce: ctx.Bool("no-introduce"),
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
		cl, err := client.NewDepsDevClient(depsdev.DepsdevAPI, "osv-scanner_fix/"+version.OSVVersion)
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

	userAgent := "osv-scanner_fix/" + version.OSVVersion
	if ctx.Bool("offline-vulnerabilities") {
		matcher, err := localmatcher.NewLocalMatcher(
			r,
			ctx.String("local-db-path"),
			userAgent,
			ctx.Bool("download-offline-databases"),
		)
		if err != nil {
			return nil, err
		}

		eco, ok := util.OSVEcosystem[system]
		if !ok {
			// Something's very wrong if we hit this
			panic("unhandled resolve.Ecosystem: " + system.String())
		}
		if _, err := matcher.LoadEcosystem(ctx.Context, ecosystem.Parsed{Ecosystem: eco}); err != nil {
			return nil, err
		}

		opts.Client.VulnerabilityMatcher = matcher
	} else {
		config := osvdev.DefaultConfig()
		config.UserAgent = userAgent
		opts.Client.VulnerabilityMatcher = &osvmatcher.CachedOSVMatcher{
			Client: osvdev.OSVClient{
				HTTPClient:  http.DefaultClient,
				Config:      config,
				BaseHostURL: osvdev.DefaultBaseURL,
			},
			InitialQueryTimeout: 5 * time.Minute,
		}
	}

	if !ctx.Bool("non-interactive") {
		return nil, interactiveMode(ctx.Context, opts)
	}

	maxUpgrades := ctx.Int("apply-top")

	strategy := strategy(ctx.String("strategy"))
	if strategy == "relock" { // renamed
		strategy = strategyRelax
	}

	if !ctx.IsSet("strategy") {
		// Choose a default strategy based on the manifest/lockfile provided.
		switch {
		case remediation.SupportsRelax(opts.ManifestRW):
			strategy = strategyRelax
		case remediation.SupportsOverride(opts.ManifestRW):
			strategy = strategyOverride
		case remediation.SupportsInPlace(opts.LockfileRW):
			strategy = strategyInPlace
		default:
			return nil, errors.New("no supported remediation strategies for manifest/lockfile")
		}
	}

	switch strategy {
	case strategyRelax:
		return r, autoRelax(ctx.Context, r, opts, maxUpgrades)
	case strategyInPlace:
		return r, autoInPlace(ctx.Context, r, opts, maxUpgrades)
	case strategyOverride:
		return r, autoOverride(ctx.Context, r, opts, maxUpgrades)
	default:
		// The strategy flag should already be validated by this point.
		panic(fmt.Sprintf("non-interactive mode attempted to run with unhandled strategy: \"%s\"", ctx.String("strategy")))
	}
}
