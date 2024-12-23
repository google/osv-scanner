package osvscanner

import (
	"fmt"

	"github.com/google/osv-scanner/internal/config"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/imodels/results"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

// filterUnscannablePackages removes packages that don't have enough information to be scanned
// e,g, local packages that specified by path
func filterUnscannablePackages(r reporter.Reporter, scanResults *results.ScanResults) {
	packageResults := make([]imodels.PackageScanResult, 0, len(scanResults.PackageScanResults))
	for _, psr := range scanResults.PackageScanResults {
		p := psr.PackageInfo

		switch {
		// If none of the cases match, skip this package since it's not scannable
		case !p.Ecosystem.IsEmpty() && p.Name != "" && p.Version != "":
		case p.Commit != "":
		default:
			continue
		}

		packageResults = append(packageResults, psr)
	}

	if len(packageResults) != len(scanResults.PackageScanResults) {
		r.Infof("Filtered %d local/unscannable package/s from the scan.\n", len(scanResults.PackageScanResults)-len(packageResults))
	}

	scanResults.PackageScanResults = packageResults
}

// filterIgnoredPackages removes ignore scanned packages according to config. Returns filtered scanned packages.
func filterIgnoredPackages(r reporter.Reporter, scanResults *results.ScanResults) {
	configManager := &scanResults.ConfigManager

	out := make([]imodels.PackageScanResult, 0, len(scanResults.PackageScanResults))
	for _, psr := range scanResults.PackageScanResults {
		p := psr.PackageInfo
		configToUse := configManager.Get(r, p.Location)

		if ignore, ignoreLine := configToUse.ShouldIgnorePackage(p); ignore {
			pkgString := fmt.Sprintf("%s/%s/%s", p.Ecosystem.String(), p.Name, p.Version)

			reason := ignoreLine.Reason
			if reason == "" {
				reason = "(no reason given)"
			}
			r.Infof("Package %s has been filtered out because: %s\n", pkgString, reason)

			continue
		}
		out = append(out, psr)
	}

	if len(out) != len(scanResults.PackageScanResults) {
		r.Infof("Filtered %d ignored package/s from the scan.\n", len(scanResults.PackageScanResults)-len(out))
	}

	scanResults.PackageScanResults = out
}

// Filters results according to config, preserving order. Returns total number of vulnerabilities removed.
func filterResults(r reporter.Reporter, results *models.VulnerabilityResults, configManager *config.Manager, allPackages bool) int {
	removedCount := 0
	newResults := []models.PackageSource{} // Want 0 vulnerabilities to show in JSON as an empty list, not null.
	for _, pkgSrc := range results.Results {
		configToUse := configManager.Get(r, pkgSrc.Source.Path)
		var newPackages []models.PackageVulns
		for _, pkgVulns := range pkgSrc.Packages {
			newVulns := filterPackageVulns(r, pkgVulns, configToUse)
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
	results.Results = newResults

	return removedCount
}

// Filters package-grouped vulnerabilities according to config, preserving ordering. Returns filtered package vulnerabilities.
func filterPackageVulns(r reporter.Reporter, pkgVulns models.PackageVulns, configToUse config.Config) models.PackageVulns {
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
					r.Infof("%s has been filtered out because: %s\n", ignoreLine.ID, reason)
				case 2:
					r.Infof("%s and 1 alias have been filtered out because: %s\n", ignoreLine.ID, reason)
				default:
					r.Infof("%s and %d aliases have been filtered out because: %s\n", ignoreLine.ID, len(group.Aliases)-1, reason)
				}

				break
			}
		}
		if !ignore {
			newGroups = append(newGroups, group)
		}
	}

	var newVulns []models.Vulnerability
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
