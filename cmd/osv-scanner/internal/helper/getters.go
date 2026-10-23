package helper

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/v2/internal/spdx"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

func GetScanLicensesAllowlist(cmd *cli.Command) ([]string, error) {
	licenses := cmd.Generic("licenses").(*allowedLicencesFlag)
	if !licenses.enabled {
		return []string{}, nil
	}

	allowlist := licenses.allowlist

	if len(allowlist) == 0 {
		return []string{}, nil
	}

	if unrecognized := spdx.Unrecognized(allowlist); len(unrecognized) > 0 {
		return nil, fmt.Errorf("--licenses requires comma-separated spdx licenses. The following license(s) are not recognized as spdx: %s", strings.Join(unrecognized, ","))
	}

	if cmd.Bool("offline") {
		allowlist = []string{}
	}

	return allowlist, nil
}

func GetCommonScannerActions(cmd *cli.Command, scanLicensesAllowlist []string) osvscanner.ScannerActions {
	callAnalysisStates := CreateCallAnalysisStates(cmd.StringSlice("call-analysis"), cmd.StringSlice("no-call-analysis"))
	licenses := cmd.Generic("licenses").(*allowedLicencesFlag)

	return osvscanner.ScannerActions{
		IncludeGitRoot:        cmd.Bool("include-git-root"),
		ConfigOverridePath:    cmd.String("config"),
		ShowAllPackages:       cmd.Bool("all-packages"),
		ShowAllVulns:          cmd.Bool("all-vulns"),
		CompareOffline:        cmd.Bool("offline-vulnerabilities"),
		DownloadDatabases:     cmd.Bool("download-offline-databases"),
		LocalDBPath:           cmd.String("local-db-path"),
		PluginNetworkDisabled: cmd.Bool("offline"),
		ScanLicensesSummary:   licenses.enabled,
		ScanLicensesAllowlist: scanLicensesAllowlist,
		CallAnalysisStates:    callAnalysisStates,
	}
}

// FallbackToDeprecatedName returns the preferred cli flag name if set,
// otherwise falling back to the deprecated name
func FallbackToDeprecatedName(cmd *cli.Command, name, old string) string {
	if cmd.IsSet(name) {
		return name
	}

	return old
}

func GetExperimentalScannerActions(cmd *cli.Command) osvscanner.ExperimentalScannerActions {
	return osvscanner.ExperimentalScannerActions{
		PluginsEnabled:         cmd.StringSlice(FallbackToDeprecatedName(cmd, "x-plugins", "experimental-plugins")),
		PluginsDisabled:        cmd.StringSlice(FallbackToDeprecatedName(cmd, "x-disable-plugins", "experimental-disable-plugins")),
		PluginsNoDefaults:      cmd.Bool(FallbackToDeprecatedName(cmd, "x-no-default-plugins", "experimental-no-default-plugins")),
		FlagDeprecatedPackages: cmd.Bool(FallbackToDeprecatedName(cmd, "x-flag-deprecated-packages", "experimental-flag-deprecated-packages")),
	}
}
