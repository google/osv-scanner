package source

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/cmd/osv-scanner/internal/helper"
	"github.com/google/osv-scanner/internal/spdx"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

var projectScanFlags = []cli.Flag{
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
	&cli.BoolFlag{
		Name:  "json",
		Usage: "sets output to json (deprecated, use --format json instead)",
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
		Name:  "experimental-resolution-data-source",
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
		Name:  "experimental-maven-registry",
		Usage: "URL of the default registry to fetch Maven metadata",
	},
}

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "source",
		Usage:       "scans a source project's dependencies for known vulnerabilities using the OSV database.",
		Description: "scans a source project's dependencies for known vulnerabilities using the OSV database.",
		Flags:       append(projectScanFlags, helper.GlobalScanFlags...),
		ArgsUsage:   "[directory1 directory2...]",
		Action: func(c *cli.Context) error {
			var err error
			*r, err = Action(c, stdout, stderr)

			return err
		},
	}
}

func Action(context *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	format := context.String("format")

	if context.Bool("json") {
		format = "json"
	}

	outputPath := context.String("output")
	serve := context.Bool("serve")
	if serve {
		format = "html"
		if outputPath == "" {
			// Create a temporary directory
			tmpDir, err := os.MkdirTemp("", "osv-scanner-result")
			if err != nil {
				return nil, fmt.Errorf("failed creating temporary directory: %w\n"+
					"Please use `--output result.html` to specify the output path", err)
			}

			// Remove the created temporary directory after
			defer os.RemoveAll(tmpDir)
			outputPath = filepath.Join(tmpDir, "index.html")
		}
	}

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
		callAnalysisStates = helper.CreateCallAnalysisStates([]string{"all"}, context.StringSlice("no-call-analysis"))
		r.Infof("Warning: the experimental-call-analysis flag has been replaced. Please use the call-analysis and no-call-analysis flags instead.\n")
	} else {
		callAnalysisStates = helper.CreateCallAnalysisStates(context.StringSlice("call-analysis"), context.StringSlice("no-call-analysis"))
	}

	scanLicensesAllowlist := context.StringSlice("experimental-licenses")
	if context.Bool("experimental-offline") {
		scanLicensesAllowlist = []string{}
	}

	scannerAction := osvscanner.ScannerActions{
		LockfilePaths:      context.StringSlice("lockfile"),
		SBOMPaths:          context.StringSlice("sbom"),
		Recursive:          context.Bool("recursive"),
		SkipGit:            context.Bool("skip-git"),
		NoIgnore:           context.Bool("no-ignore"),
		ConfigOverridePath: context.String("config"),
		DirectoryPaths:     context.Args().Slice(),
		CallAnalysisStates: callAnalysisStates,
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			LocalDBPath:       context.String("experimental-local-db-path"),
			DownloadDatabases: context.Bool("experimental-download-offline-databases"),
			CompareOffline:    context.Bool("experimental-offline-vulnerabilities"),
			// License summary mode causes all
			// packages to appear in the json as
			// every package has a license - even
			// if it's just the UNKNOWN license.
			ShowAllPackages: context.Bool("experimental-all-packages") ||
				context.Bool("experimental-licenses-summary"),
			ScanLicensesSummary:   context.Bool("experimental-licenses-summary"),
			ScanLicensesAllowlist: scanLicensesAllowlist,
			TransitiveScanningActions: osvscanner.TransitiveScanningActions{
				Disabled:         context.Bool("experimental-no-resolve"),
				NativeDataSource: context.String("experimental-resolution-data-source") == "native",
				MavenRegistry:    context.String("experimental-maven-registry"),
			},
		},
	}

	var vulnResult models.VulnerabilityResults
	vulnResult, err = osvscanner.DoScan(scannerAction, r)

	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return r, err
	}

	if errPrint := r.PrintResult(&vulnResult); errPrint != nil {
		return r, fmt.Errorf("failed to write output: %w", errPrint)
	}

	// Auto-open outputted HTML file for users.
	if outputPath != "" {
		if serve {
			helper.ServeHTML(r, outputPath)
		} else if format == "html" {
			helper.OpenHTML(r, outputPath)
		}
	}

	// This may be nil.
	return r, err
}
