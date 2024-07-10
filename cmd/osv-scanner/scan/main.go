package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/google/osv-scanner/pkg/spdx"
	"golang.org/x/term"

	"github.com/urfave/cli/v2"
)

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "scan",
		Usage:       "scans various mediums for dependencies and matches it against the OSV database",
		Description: "scans various mediums for dependencies and matches it against the OSV database",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:      "docker",
				Aliases:   []string{"D"},
				Usage:     "scan docker image with this name. Warning: Only run this on a trusted container image, as it runs the container image to retrieve the package versions",
				TakesFile: false,
			},
			&cli.StringSliceFlag{
				Name:      "lockfile",
				Aliases:   []string{"L"},
				Usage:     "scan package lockfile on this path",
				TakesFile: true,
			},
			&cli.StringSliceFlag{
				Name:      "sbom",
				Aliases:   []string{"S"},
				Usage:     "scan sbom file on this path",
				TakesFile: true,
			},
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
				Action: func(context *cli.Context, s string) error {
					if slices.Contains(reporter.Format(), s) {
						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
				},
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "sets output to json (deprecated, use --format json instead)",
			},
			&cli.StringFlag{
				Name:      "output",
				Usage:     "saves the result to the given file path",
				TakesFile: true,
			},
			&cli.BoolFlag{
				Name:  "skip-git",
				Usage: "skip scanning git repositories",
				Value: false,
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "check subdirectories",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:  "experimental-call-analysis",
				Usage: "[Deprecated] attempt call analysis on code to detect only active vulnerabilities",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "no-ignore",
				Usage: "also scan files that would be ignored by .gitignore",
				Value: false,
			},
			&cli.StringSliceFlag{
				Name:  "call-analysis",
				Usage: "attempt call analysis on code to detect only active vulnerabilities",
			},
			&cli.StringSliceFlag{
				Name:  "no-call-analysis",
				Usage: "disables call graph analysis",
			},
			&cli.StringFlag{
				Name:  "verbosity",
				Usage: "specify the level of information that should be provided during runtime; value can be: " + strings.Join(reporter.VerbosityLevels(), ", "),
				Value: "info",
			},
			&cli.BoolFlag{
				Name:  "experimental-offline",
				Usage: "checks for vulnerabilities using local databases that are already cached",
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
			&cli.BoolFlag{
				Name:  "experimental-all-packages",
				Usage: "when json output is selected, prints all packages",
			},
			&cli.BoolFlag{
				Name:  "experimental-licenses-summary",
				Usage: "report a license summary, implying the --experimental-all-packages flag",
			},
			&cli.StringSliceFlag{
				Name:  "experimental-licenses",
				Usage: "report on licenses based on an allowlist",
			},
			&cli.StringFlag{
				Name:      "experimental-oci-image",
				Usage:     "scan an exported *docker* container image archive (exported using `docker save` command) file",
				TakesFile: true,
				Hidden:    true,
			},
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(c *cli.Context) error {
			var err error
			*r, err = action(c, stdout, stderr)

			return err
		},
	}
}

func action(context *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	format := context.String("format")

	if context.Bool("json") {
		format = "json"
	}

	outputPath := context.String("output")

	termWidth := 0
	var err error
	if outputPath != "" { // Output is definitely a file
		stdout, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
	} else { // Output might be a terminal
		if stdoutAsFile, ok := stdout.(*os.File); ok {
			termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
			if err != nil { // If output is not a terminal,
				termWidth = 0
			}
		}
	}

	if context.Bool("experimental-licenses-summary") && context.IsSet("experimental-licenses") {
		return nil, errors.New("--experimental-licenses-summary and --experimental-licenses flags cannot be set")
	}
	allowlist := context.StringSlice("experimental-licenses")
	if context.IsSet("experimental-licenses") {
		if len(allowlist) == 0 ||
			(len(allowlist) == 1 && allowlist[0] == "") {
			return nil, errors.New("--experimental-licenses requires at least one value")
		}
		if unrecognized := spdx.Unrecognized(allowlist); len(unrecognized) > 0 {
			return nil, fmt.Errorf("--experimental-licenses requires comma-separated spdx licenses. The following license(s) are not recognized as spdx: %s", strings.Join(unrecognized, ","))
		}
	}

	verbosityLevel, err := reporter.ParseVerbosityLevel(context.String("verbosity"))
	if err != nil {
		return nil, err
	}
	r, err := reporter.New(format, stdout, stderr, verbosityLevel, termWidth)
	if err != nil {
		return r, err
	}

	var callAnalysisStates map[string]bool
	if context.IsSet("experimental-call-analysis") {
		callAnalysisStates = createCallAnalysisStates([]string{"all"}, context.StringSlice("no-call-analysis"))
		r.Infof("Warning: the experimental-call-analysis flag has been replaced. Please use the call-analysis and no-call-analysis flags instead.\n")
	} else {
		callAnalysisStates = createCallAnalysisStates(context.StringSlice("call-analysis"), context.StringSlice("no-call-analysis"))
	}

	vulnResult, err := osvscanner.DoScan(osvscanner.ScannerActions{
		LockfilePaths:        context.StringSlice("lockfile"),
		SBOMPaths:            context.StringSlice("sbom"),
		DockerContainerNames: context.StringSlice("docker"),
		Recursive:            context.Bool("recursive"),
		SkipGit:              context.Bool("skip-git"),
		NoIgnore:             context.Bool("no-ignore"),
		ConfigOverridePath:   context.String("config"),
		DirectoryPaths:       context.Args().Slice(),
		CallAnalysisStates:   callAnalysisStates,
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			LocalDBPath:       context.String("experimental-local-db-path"),
			DownloadDatabases: context.Bool("experimental-download-offline-databases"),
			CompareOffline:    context.Bool("experimental-offline"),
			// License summary mode causes all
			// packages to appear in the json as
			// every package has a license - even
			// if it's just the UNKNOWN license.
			ShowAllPackages: context.Bool("experimental-all-packages") ||
				context.Bool("experimental-licenses-summary"),
			ScanLicensesSummary:   context.Bool("experimental-licenses-summary"),
			ScanLicensesAllowlist: context.StringSlice("experimental-licenses"),
			ScanOCIImage:          context.String("experimental-oci-image"),
		},
	}, r)

	if err != nil && !errors.Is(err, osvscanner.VulnerabilitiesFoundErr) {
		return r, err
	}

	if errPrint := r.PrintResult(&vulnResult); errPrint != nil {
		return r, fmt.Errorf("failed to write output: %w", errPrint)
	}

	// This may be nil.
	return r, err
}
