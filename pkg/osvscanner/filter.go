// Package osvscanner provides the main logic for the OSV-Scanner.
package osvscanner

import (
	"fmt"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/imodels/results"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// filterUnscannablePackages removes packages that don't have enough information to be scanned or
// are not a supported ecosystem
// e,g, local packages that specified by path
func filterUnscannablePackages(scanResults *results.ScanResults) {
	packageResults := make([]imodels.PackageScanResult, 0, len(scanResults.PackageScanResults))
	for _, psr := range scanResults.PackageScanResults {
		p := psr.PackageInfo

		switch {
		// If **none** of the cases match, skip this package since it's not scannable
		case !p.Ecosystem().IsEmpty() && p.Name() != "" && p.Version() != "":
		case p.Commit() != "":
		default:
			continue
		}

		switch {
		// If **any** of the following cases are true, skip this package
		case p.Ecosystem().Ecosystem == osvschema.EcosystemMaven && p.Name() == "unknown", // Is Maven with package name unknown
			p.Ecosystem().GetValidity() != nil && !p.Ecosystem().IsEmpty(): // Is invalid and not empty
			continue
		}

		packageResults = append(packageResults, psr)
	}

	if len(packageResults) != len(scanResults.PackageScanResults) {
		cmdlogger.Infof("Filtered %d local/unscannable package/s from the scan.", len(scanResults.PackageScanResults)-len(packageResults))
	}

	scanResults.PackageScanResults = packageResults
}

// filterNonContainerRelevantPackages removes packages that are not relevant when doing container scanning
func filterNonContainerRelevantPackages(scanResults *results.ScanResults) {
	packageResults := make([]imodels.PackageScanResult, 0, len(scanResults.PackageScanResults))
	for _, psr := range scanResults.PackageScanResults {
		p := psr.PackageInfo

		// Almost all packages with linux as a SourceName are kernel packages
		// which does not apply within a container, as containers use the host's kernel
		if p.Name() == "linux" {
			continue
		}

		packageResults = append(packageResults, psr)
	}

	if len(packageResults) != len(scanResults.PackageScanResults) {
		cmdlogger.Infof("Filtered %d non container relevant package/s from the scan.", len(scanResults.PackageScanResults)-len(packageResults))
	}

	scanResults.PackageScanResults = packageResults
}

// filterIgnoredPackages removes ignore scanned packages according to config. Returns filtered scanned packages.
func filterIgnoredPackages(scanResults *results.ScanResults) {
	configManager := &scanResults.ConfigManager

	out := make([]imodels.PackageScanResult, 0, len(scanResults.PackageScanResults))
	for _, psr := range scanResults.PackageScanResults {
		p := psr.PackageInfo
		configToUse := configManager.Get(p.Location())

		if ignore, ignoreLine := configToUse.ShouldIgnorePackage(p); ignore {
			pkgString := fmt.Sprintf("%s/%s/%s", p.Ecosystem().String(), p.Name(), p.Version())

			reason := ignoreLine.Reason
			if reason == "" {
				reason = "(no reason given)"
			}
			cmdlogger.Infof("Package %s has been filtered out because: %s", pkgString, reason)

			continue
		}
		out = append(out, psr)
	}

	if len(out) != len(scanResults.PackageScanResults) {
		cmdlogger.Infof("Filtered %d ignored package/s from the scan.", len(scanResults.PackageScanResults)-len(out))
	}

	scanResults.PackageScanResults = out
}

// Filters results according to config, preserving order. Returns total number of vulnerabilities removed.
func filterResults(vulnResults *models.VulnerabilityResults, configManager *config.Manager, allPackages bool) int {
	removedCount := 0
	newResults := []models.PackageSource{} // Want 0 vulnerabilities to show in JSON as an empty list, not null.
	for _, pkgSrc := range vulnResults.Results {
		configToUse := configManager.Get(pkgSrc.Source.Path)
		var newPackages []models.PackageVulns
		for _, pkgVulns := range pkgSrc.Packages {
			newVulns := filterPackageVulns(pkgVulns, configToUse)
			removedCount += len(pkgVulns.Vulnerabilities) - len(newVulns.Vulnerabilities)
			if allPackages || len(newVulns.Vulnerabilities) > 0 || len(pkgVulns.LicenseViolations) > 0 {
				newPackages = append(newPackages, newVulns)
			}
		}
		// Don't want to include the package source at all if there are no vulns.
		if len(newPackages) > 0 {
			pkgSrc.Packages = newPackages
			newResults = append(newResults, pkgSrc)
		}
	}
	vulnResults.Results = newResults

	return removedCount
}

// Filters package-grouped vulnerabilities according to config, preserving ordering. Returns filtered package vulnerabilities.
func filterPackageVulns(pkgVulns models.PackageVulns, configToUse config.Config) models.PackageVulns {
	ignoredVulns := map[string]struct{}{}

	// Iterate over groups first to remove all aliases of ignored vulnerabilities.
	var newGroups []models.GroupInfo
	for _, group := range pkgVulns.Groups {
		ignore := false
		for _, id := range group.Aliases {
			var ignoreLine config.IgnoreEntry
			if ignore, ignoreLine = configToUse.ShouldIgnore(id); ignore {
				for _, id := range group.Aliases {
					ignoredVulns[id] = struct{}{}
				}

				reason := ignoreLine.Reason

				if reason == "" {
					reason = "(no reason given)"
				}

				// NB: This only prints the first reason encountered in all the aliases.
				switch len(group.Aliases) {
				case 1:
					cmdlogger.Infof("%s has been filtered out because: %s", ignoreLine.ID, reason)
				case 2:
					cmdlogger.Infof("%s and 1 alias have been filtered out because: %s", ignoreLine.ID, reason)
				default:
					cmdlogger.Infof("%s and %d aliases have been filtered out because: %s", ignoreLine.ID, len(group.Aliases)-1, reason)
				}

				ignoreLine.MarkAsUsed()

				break
			}
		}
		if !ignore {
			newGroups = append(newGroups, group)
		}
	}

	var newVulns []osvschema.Vulnerability
	if len(newGroups) > 0 { // If there are no groups left then there would be no vulnerabilities.
		for _, vuln := range pkgVulns.Vulnerabilities {
			if _, filtered := ignoredVulns[vuln.ID]; !filtered {
				newVulns = append(newVulns, vuln)
			}
		}
	}

	// Passed by value. We don't want to alter the original PackageVulns.
	pkgVulns.Groups = newGroups
	pkgVulns.Vulnerabilities = newVulns

	return pkgVulns
}
