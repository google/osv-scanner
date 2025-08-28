package helper

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/reporter"
	"github.com/urfave/cli/v3"
)

// offlineFlags is a map of flags which require network access to operate,
// with the values to set them to in order to disable them
var offlineFlags = map[string]string{
	"offline-vulnerabilities": "true",
	"no-resolve":              "true",
}

// a "boolean or list" flag whose presence indicates a summary of licenses should
// be printed, and whose (optional) value will be a comma-delimited list of licenses
// that should be considered allowed
type allowedLicencesFlag struct {
	allowlist []string
}

func (g *allowedLicencesFlag) Get() any {
	return g
}

func (g *allowedLicencesFlag) Set(value string) error {
	if value == "" || value == "false" || value == "true" {
		g.allowlist = nil
	} else {
		g.allowlist = strings.Split(value, ",")
	}

	return nil
}

// IsBoolFlag indicates that it is valid to use this flag in a boolean context
// and is what lets us accept both enable/disable and list-of-licenses values
func (g *allowedLicencesFlag) IsBoolFlag() bool {
	return true
}

func (g *allowedLicencesFlag) String() string {
	return strings.Join(g.allowlist, ",")
}

// BuildCommonScanFlags returns a slice of flags which are common to all scan (sub)commands
func BuildCommonScanFlags(defaultExtractors []string) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:      "config",
			Usage:     "set/override config file",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:    "format",
			Aliases: []string{"f"},
			Usage:   "sets the output format; value can be: " + strings.Join(reporter.Format(), ", "),
			Value:   "table",
			Action: func(_ context.Context, _ *cli.Command, s string) error {
				if slices.Contains(reporter.Format(), s) {
					if s != "vertical" && s != "table" && s != "markdown" {
						cmdlogger.SendEverythingToStderr()
					}

					return nil
				}

				return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
			},
		},
		&cli.BoolFlag{
			Name:  "serve",
			Usage: "output as HTML result and serve it locally",
		},
		&cli.StringFlag{
			Name:  "port",
			Usage: "port number to use when serving HTML report (default: 8000)",
			Action: func(_ context.Context, _ *cli.Command, p string) error {
				servePort = p
				return nil
			},
		},
		&cli.StringFlag{
			Name:      "output",
			Usage:     "saves the result to the given file path",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:  "verbosity",
			Usage: "specify the level of information that should be provided during runtime; value can be: " + strings.Join(cmdlogger.Levels(), ", "),
			Value: "info",
			Action: func(_ context.Context, _ *cli.Command, s string) error {
				lvl, err := cmdlogger.ParseLevel(s)

				if err != nil {
					return err
				}

				cmdlogger.SetLevel(lvl)

				return nil
			},
		},
		&cli.BoolFlag{
			Name:  "offline",
			Usage: "run in offline mode, disabling any features requiring network access",
			Action: func(_ context.Context, cmd *cli.Command, b bool) error {
				if !b {
					return nil
				}
				// Disable the features requiring network access.
				for flag, value := range offlineFlags {
					// TODO(michaelkedar): do something if the flag was already explicitly set.

					// Skip setting the flag if the current command doesn't have it.
					if !slices.ContainsFunc(cmd.Flags, func(f cli.Flag) bool {
						return slices.Contains(f.Names(), flag)
					}) {
						continue
					}

					if err := cmd.Set(flag, value); err != nil {
						panic(fmt.Sprintf("failed setting offline flag %s to %s: %v", flag, value, err))
					}
				}

				return nil
			},
		},
		&cli.BoolFlag{
			Name:  "offline-vulnerabilities",
			Usage: "checks for vulnerabilities using local databases that are already cached",
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
		&cli.StringSliceFlag{
			Name:  "call-analysis",
			Usage: "attempt call analysis on code to detect only active vulnerabilities",
		},
		&cli.StringSliceFlag{
			Name:  "no-call-analysis",
			Usage: "disables call graph analysis",
		},
		&cli.BoolFlag{
			Name:  "no-resolve",
			Usage: "disable transitive dependency resolution of manifest files",
		},
		&cli.BoolFlag{
			Name:  "allow-no-lockfiles",
			Usage: "has the scanner consider no lockfiles being found as ok",
		},
		&cli.BoolFlag{
			Name:  "all-packages",
			Usage: "when json output is selected, prints all packages",
		},
		&cli.BoolFlag{
			Name:  "all-vulns",
			Usage: "show all vulnerabilities including unimportant and uncalled ones",
		},
		&cli.GenericFlag{
			Name:  "licenses",
			Usage: "report on licenses based on an allowlist",
			Value: &allowedLicencesFlag{},
		},
		&cli.StringSliceFlag{
			Name:  "experimental-plugins",
			Usage: "list of specific plugins and presets of plugins to use",
			Value: defaultExtractors,
		},
		&cli.StringSliceFlag{
			Name:  "experimental-disable-plugins",
			Usage: "list of specific plugins and presets of plugins to not use",
		},
		&cli.BoolFlag{
			Name:  "experimental-no-default-plugins",
			Usage: "disable default plugins, instead using only those enabled by --experimental-plugins",
		},
	}
}
