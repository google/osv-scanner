package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/google/osv-scanner/pkg/spdx"
	"golang.org/x/term"

	"github.com/urfave/cli/v2"
)

func ScanAction(context *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
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
		return nil, fmt.Errorf("--experimental-licenses-summary and --experimental-licenses flags cannot be set")
	}
	allowlist := context.StringSlice("experimental-licenses")
	if context.IsSet("experimental-licenses") {
		if len(allowlist) == 0 ||
			(len(allowlist) == 1 && allowlist[0] == "") {
			return nil, fmt.Errorf("--experimental-licenses requires at least one value")
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
			LocalDBPath:    context.String("experimental-local-db-path"),
			CompareLocally: context.Bool("experimental-local-db"),
			CompareOffline: context.Bool("experimental-offline"),
			// License summary mode causes all
			// packages to appear in the json as
			// every package has a license - even
			// if it's just the UNKNOWN license.
			ShowAllPackages: context.Bool("experimental-all-packages") ||
				context.Bool("experimental-licenses-summary"),
			ScanLicensesSummary:   context.Bool("experimental-licenses-summary"),
			ScanLicensesAllowlist: context.StringSlice("experimental-licenses"),
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
