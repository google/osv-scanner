package fix

import (
	"encoding/json"
	"io"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

func printResult(outputResult result.Result, outputJSON bool, stdout io.Writer) error {
	if outputJSON {
		return outputJSONResult(stdout, outputResult)
	}

	return outputText(stdout, outputResult)
}

func outputText(_ io.Writer, out result.Result) error {
	if len(out.Errors) > 0 {
		cmdlogger.Warnf("WARNING: encountered %d errors during dependency resolution:", len(out.Errors))
		for _, err := range out.Errors {
			cmdlogger.Errorf("Error when resolving %s@%s:", err.Package.Name, err.Package.Version)
			if strings.Contains(err.Requirement.Version, ":") {
				// this will be the case with unsupported npm requirements e.g. `file:...`, `git+https://...`
				// TODO: don't rely on resolution to propagate these errors
				// No easy access to the `knownAs` field to find which package this corresponds to
				cmdlogger.Errorf("\tSkipped resolving unsupported version specification: %s", err.Requirement.Version)
			} else {
				cmdlogger.Errorf("\t%v: %s@%s", err.Error, err.Requirement.Name, err.Requirement.Version)
			}
		}
	}

	nVulns := len(out.Vulnerabilities)

	cmdlogger.Infof("Found %d vulnerabilities matching the filter", nVulns)

	if len(out.Patches) == 0 {
		cmdlogger.Infof("No dependency patches are possible")
		cmdlogger.Infof("REMAINING-VULNS: %d", nVulns)
		cmdlogger.Infof("UNFIXABLE-VULNS: %d", nVulns)

		return nil
	}

	changedDeps := 0
	var fixedVulns []string
	for _, patch := range out.Patches {
		changedDeps += len(patch.PackageUpdates)
		for _, v := range patch.Fixed {
			fixedVulns = append(fixedVulns, v.ID)
		}
	}

	if out.Strategy == strategy.StrategyOverride {
		cmdlogger.Infof("Can fix %d/%d matching vulnerabilities by overriding %d dependencies", len(fixedVulns), nVulns, changedDeps)
		for _, patch := range out.Patches {
			for _, pkg := range patch.PackageUpdates {
				cmdlogger.Infof("OVERRIDE-PACKAGE: %s,%s", pkg.Name, pkg.VersionTo)
			}
		}
	} else {
		cmdlogger.Infof("Can fix %d/%d matching vulnerabilities by changing %d dependencies", len(fixedVulns), nVulns, changedDeps)
		for _, patch := range out.Patches {
			for _, pkg := range patch.PackageUpdates {
				cmdlogger.Infof("UPGRADED-PACKAGE: %s,%s,%s", pkg.Name, pkg.VersionFrom, pkg.VersionTo)
			}
		}
	}
	slices.Sort(fixedVulns)
	cmdlogger.Infof("FIXED-VULN-IDS: %s", strings.Join(fixedVulns, ","))
	cmdlogger.Infof("REMAINING-VULNS: %d", nVulns-len(fixedVulns))

	nUnfixable := 0
	for _, v := range out.Vulnerabilities {
		if v.Unactionable {
			nUnfixable++
		}
	}
	cmdlogger.Infof("UNFIXABLE-VULNS: %d", nUnfixable)

	return nil
}

func outputJSONResult(w io.Writer, out result.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(out)
}
