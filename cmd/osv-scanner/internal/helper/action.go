package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

// Action runs a scan using the flags on cmd, with subcommand-specific behavior
// supplied through customizeActions and runScanner, and then writes the results.
func Action(
	_ context.Context,
	cmd *cli.Command,
	stdout, stderr io.Writer,
	clientFactories scalibrconfig.ClientFactories,
	customizeActions func(actions *osvscanner.ScannerActions),
	runScanner func(actions osvscanner.ScannerActions) (models.VulnerabilityResults, error),
) error {
	format := cmd.String("format")
	outputPath := cmd.String(FallbackToDeprecatedName(cmd, "output-file", "output"))
	serve := cmd.Bool("serve")
	if serve {
		format = "html"
		if outputPath == "" {
			// Create a temporary directory
			tmpDir, err := os.MkdirTemp("", "osv-scanner-result")
			if err != nil {
				return fmt.Errorf("failed creating temporary directory: %w\n"+
					"Please use `--output-file result.html` to specify the output path", err)
			}

			// Remove the created temporary directory after
			defer os.RemoveAll(tmpDir)
			outputPath = filepath.Join(tmpDir, "index.html")
		}
	}

	scanLicensesAllowlist, err := GetScanLicensesAllowlist(cmd)
	if err != nil {
		return err
	}

	scannerActions := GetCommonScannerActions(cmd, scanLicensesAllowlist)
	scannerActions.ExperimentalScannerActions = GetExperimentalScannerActions(cmd)

	if clientFactories != nil {
		scannerActions.ScalibrConfig = &scalibrconfig.PluginConfig{
			ClientFactories: clientFactories,
		}
	}

	customizeActions(&scannerActions)

	var vulnResult models.VulnerabilityResults
	vulnResult, err = runScanner(scannerActions)

	// ensure that the results property is always an array
	//goland:noinspection GoDfaErrorMayBeNotNil // false positive
	if vulnResult.Results == nil {
		vulnResult.Results = []models.PackageSource{}
	}

	if cmd.Bool("allow-no-lockfiles") && errors.Is(err, osvscanner.ErrNoPackagesFound) {
		cmdlogger.Warnf("No package sources found")
		err = nil
	}

	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return err
	}

	if errPrint := PrintResult(stdout, stderr, outputPath, format, &vulnResult, scannerActions.ShowAllVulns); errPrint != nil {
		return fmt.Errorf("failed to write output: %w", errPrint)
	}

	// Auto-open outputted HTML file for users.
	if outputPath != "" {
		if serve {
			ServeHTML(outputPath)
		} else if format == "html" {
			cmdlogger.Infof("HTML output available at: %s", outputPath)
		}
	}

	// This may be nil.
	return err
}
