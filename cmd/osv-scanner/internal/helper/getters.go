package helper

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/v2/internal/spdx"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

func GetScanLicensesAllowlist(cmd *cli.Command) ([]string, error) {
	if !cmd.IsSet("licenses") {
		return []string{}, nil
	}

	allowlist := cmd.Generic("licenses").(*allowedLicencesFlag).allowlist

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

	return osvscanner.ScannerActions{
		IncludeGitRoot:     cmd.Bool("include-git-root"),
		ConfigOverridePath: cmd.String("config"),
		ShowAllPackages:    cmd.Bool("all-packages"),
		ShowAllVulns:       cmd.Bool("all-vulns"),

		CompareOffline:        cmd.Bool("offline-vulnerabilities"),
		DownloadDatabases:     cmd.Bool("download-offline-databases"),
		LocalDBPath:           cmd.String("local-db-path"),
		ScanLicensesSummary:   cmd.IsSet("licenses"),
		ScanLicensesAllowlist: scanLicensesAllowlist,
		CallAnalysisStates:    callAnalysisStates,
	}
}

func GetExperimentalScannerActions(cmd *cli.Command) osvscanner.ExperimentalScannerActions {
	return osvscanner.ExperimentalScannerActions{
		PluginsEnabled:    cmd.StringSlice("experimental-plugins"),
		PluginsDisabled:   cmd.StringSlice("experimental-disable-plugins"),
		PluginsNoDefaults: cmd.Bool("experimental-no-default-plugins"),
	}
}
