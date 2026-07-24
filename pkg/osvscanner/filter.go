package osvscanner

import (
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

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
			if allPackages || len(newVulns.Vulnerabilities) > 0 || len(pkgVulns.LicenseViolations) > 0 || pkgVulns.Package.Deprecated {
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
			var ignoreLine *config.IgnoreEntry
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

	var newVulns []*osvschema.Vulnerability
	if len(newGroups) > 0 { // If there are no groups left then there would be no vulnerabilities.
		for _, vuln := range pkgVulns.Vulnerabilities {
			if _, filtered := ignoredVulns[vuln.GetId()]; !filtered {
				newVulns = append(newVulns, vuln)
			}
		}
	}

	// Passed by value. We don't want to alter the original PackageVulns.
	pkgVulns.Groups = newGroups
	pkgVulns.Vulnerabilities = newVulns

	return pkgVulns
}
