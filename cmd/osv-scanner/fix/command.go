// Package fix implements the `fix` command for osv-scanner.
// It scans a manifest and/or lockfile for vulnerabilities and suggests changes for remediating them.
package fix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
	"github.com/charmbracelet/glamour/styles"
	"github.com/charmbracelet/lipgloss"
	"osv.dev/bindings/go/osvdev"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/resolution"
	scalibrOsvdev "github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/guidedremediation"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/depsdev"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

var strategies = []string{string(strategy.StrategyInPlace), string(strategy.StrategyRelax), string(strategy.StrategyOverride)}

const (
	vulnCategory     = "Vulnerability Selection Options:"
	upgradeCategory  = "Dependency Upgrade Options:"
	autoModeCategory = "non-interactive options:" // intentionally lowercase to force it to sort after the other categories
)

func Command(stdout, stderr io.Writer, _ *http.Client) *cli.Command {
	return &cli.Command{
		Name:        "fix",
		Usage:       "scans a manifest and/or lockfile for vulnerabilities and suggests changes for remediating them",
		Description: "scans a manifest and/or lockfile for vulnerabilities and suggests changes for remediating them",
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
				Action: func(_ context.Context, _ *cli.Command, s string) error {
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
				Name:   "non-interactive",
				Usage:  "[DEPRECATED] run in the non-interactive mode",
				Hidden: true,
				Value:  true,
			},
			&cli.BoolFlag{
				Name:  "interactive",
				Usage: "run in the interactive mode",
				Action: func(_ context.Context, _ *cli.Command, b bool) error {
					if b && !term.IsTerminal(int(os.Stdin.Fd())) {
						return errors.New("interactive mode only to be run in a terminal")
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "sets the non-interactive output format; value can be: text, json",
				Value:   "text",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if s == "text" || s == "json" {
						if s == "json" {
							cmdlogger.SendEverythingToStderr()
						}

						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: text, json", s)
				},
			},
			&cli.StringFlag{
				Category: autoModeCategory,
				Name:     "strategy",
				Usage:    "remediation approach to use; value can be: " + strings.Join(strategies, ", "),
				Action: func(_ context.Context, cmd *cli.Command, s string) error {
					switch strategy.Strategy(s) {
					case strategy.StrategyInPlace:
						if !cmd.IsSet("lockfile") {
							return fmt.Errorf("%s strategy requires lockfile", strategy.StrategyInPlace)
						}
					case strategy.Strategy("relock"): // renamed
						fallthrough
					case strategy.StrategyRelax:
						if !cmd.IsSet("manifest") {
							return fmt.Errorf("%s strategy requires manifest file", strategy.StrategyRelax)
						}
					case strategy.StrategyOverride:
						if !cmd.IsSet("manifest") {
							return fmt.Errorf("%s strategy requires manifest file", strategy.StrategyOverride)
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
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return action(ctx, cmd, stdout, stderr)
		},
	}
}

func action(ctx context.Context, cmd *cli.Command, stdout, stderr io.Writer) error {
	if !cmd.IsSet("manifest") && !cmd.IsSet("lockfile") {
		return errors.New("manifest or lockfile is required")
	}

	opts := options.FixVulnsOptions{
		RemediationOptions: options.RemediationOptions{
			ResolutionOptions: options.ResolutionOptions{
				MavenManagement: cmd.Bool("maven-fix-management"),
			},
			IgnoreVulns:   cmd.StringSlice("ignore-vulns"),
			ExplicitVulns: cmd.StringSlice("vulns"),
			DevDeps:       !cmd.Bool("ignore-dev"),
			MinSeverity:   cmd.Float64("min-severity"),
			MaxDepth:      cmd.Int("max-depth"),
			UpgradeConfig: upgrade.NewConfigFromStrings(cmd.StringSlice("upgrade-config")),
		},
		Manifest:          cmd.String("manifest"),
		Lockfile:          cmd.String("lockfile"),
		Strategy:          strategy.Strategy(cmd.String("strategy")),
		MaxUpgrades:       cmd.Int("apply-top"),
		NoIntroduce:       cmd.Bool("no-introduce"),
		NoMavenNewDepMgmt: false,
	}

	if opts.Strategy == "relock" {
		opts.Strategy = strategy.StrategyRelax
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
	userAgent := "osv-scanner_fix/" + version.OSVVersion
	switch cmd.String("data-source") {
	case "deps.dev":
		cl, err := client.NewDepsDevClient(depsdev.DepsdevAPI, userAgent)
		if err != nil {
			return err
		}
		opts.ResolveClient = cl

	case "native":
		var workDir string
		// Prefer to use the manifest's directory if available.
		if opts.Manifest != "" {
			workDir = filepath.Dir(opts.Manifest)
		} else {
			workDir = filepath.Dir(opts.Lockfile)
		}
		cl, err := resolution.NewCombinedNativeClient(resolution.CombinedNativeClientOptions{
			ProjectDir:    workDir,
			MavenRegistry: cmd.String("maven-registry"),
		})
		if err != nil {
			return err
		}
		opts.ResolveClient = cl
	}

	
	if cmd.Bool("offline-vulnerabilities") {
		return errors.New("not implemented")
		// matcher, err := localmatcher.NewLocalMatcher(
		// 	cmd.String("local-db-path"),
		// 	userAgent,
		// 	cmd.Bool("download-offline-databases"),
		// )
		// if err != nil {
		// 	return err
		// }

		// eco, ok := util.OSVEcosystem[system]
		// if !ok {
		// 	// Something's very wrong if we hit this
		// 	panic("unhandled resolve.Ecosystem: " + system.String())
		// }
		// if err := matcher.LoadEcosystem(ctx, osvecosystem.Parsed{Ecosystem: eco}); err != nil {
		// 	return err
		// }

		// opts.Client.VulnerabilityMatcher = matcher
	} else {
		osvdevCl := osvdev.DefaultClient()
		osvdevCl.Config.UserAgent = userAgent
		opts.VulnEnricher = scalibrOsvdev.NewWithClient(osvdevCl, 5*time.Minute)
	}

	if cmd.Bool("interactive") {
		return guidedremediation.FixVulnsInteractive(opts, GlamourRenderer{})
	}

	res, err := guidedremediation.FixVulns(opts)
	if err != nil {
		return err
	}

	outputJSON := cmd.String("format") == "json"
	return printResult(res, outputJSON, stdout)
}

type GlamourRenderer struct{}

func (GlamourRenderer) Render(details string, width int) (string, error) {
	var style ansi.StyleConfig
	if lipgloss.HasDarkBackground() {
		style = styles.DarkStyleConfig
	} else {
		style = styles.LightStyleConfig
	}
	*style.Document.Margin = 0
	style.Document.BlockPrefix = ""

	r, err := glamour.NewTermRenderer(
		glamour.WithStyles(style),
		glamour.WithWordWrap(width),
	)
	if err != nil {
		return "", err
	}
	return r.Render(details)
}
