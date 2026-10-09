package grouper

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func calculateMaxSeverity(group models.GroupInfo, pkg models.PackageVulns) string {
	var maxSeverity float64 = -1
	for _, vulnID := range group.IDs {
		var severities []*osvschema.Severity
		for _, vuln := range pkg.Vulnerabilities {
			if vuln.GetId() == vulnID {
				severities = vuln.GetSeverity()
			}
		}
		score, _, _ := severity.CalculateOverallScore(severities)
		maxSeverity = max(maxSeverity, score)
	}

	if maxSeverity < 0 {
		return ""
	}

	return fmt.Sprintf("%.1f", maxSeverity)
}

func Build(pkg models.PackageVulns, considerExploitabilitySignals bool) []models.GroupInfo {
	grouped := Group(ConvertVulnerabilityToIDAliases(pkg.Vulnerabilities))
	for i, group := range grouped {
		grouped[i].MaxSeverity = calculateMaxSeverity(group, pkg)
	}

	// For Debian-based ecosystems, mark unimportant vulnerabilities within the package.
	// Debian ecosystems may be listed with a version number, such as "Debian:10".
	if strings.HasPrefix(pkg.Package.Ecosystem, string(osvconstants.EcosystemDebian)) ||
		strings.HasPrefix(pkg.Package.Ecosystem, string(osvconstants.EcosystemUbuntu)) {
		setUnimportant(pkg, grouped)
	}

	if considerExploitabilitySignals {
		setUncalled(pkg, grouped)
	}

	return grouped
}

func setUnimportant(pkg models.PackageVulns, grouped []models.GroupInfo) {
	for _, vuln := range pkg.Vulnerabilities {
		if !isUnimportant(vuln) {
			continue
		}
		for i := range grouped {
			if slices.Contains(grouped[i].IDs, vuln.GetId()) {
				if grouped[i].ExperimentalAnalysis == nil {
					grouped[i].ExperimentalAnalysis = make(map[string]models.AnalysisInfo)
				}
				// Set unimportant vulns as uncalled
				grouped[i].ExperimentalAnalysis[vuln.GetId()] = models.AnalysisInfo{
					Unimportant: true,
					// TODO(gongh@): Currently, call analysis is not supported for Linux distribution vulnerabilities.
					// Except explicitly set Called as true to not be counted as uncalled vulnerabilities.
					// Update this behavior when call analysis for Linux distributions is implemented.
					Called: true,
				}

				break
			}
		}
	}
}

// isUnimportant checks if a Debian-based vulnerability is tagged as unimportant
// Debian: https://security-team.debian.org/security_tracker.html#severity-levels
// Ubuntu: https://ubuntu.com/security/cves/about#priority
func isUnimportant(vuln *osvschema.Vulnerability) bool {
	for _, sev := range vuln.GetSeverity() {
		// TODO(gongh@): remove checking empty severity type after all ubuntu records have a valid severity tag.
		if strings.HasPrefix(vuln.GetId(), "UBUNTU-CVE-") &&
			(sev.GetType() == osvschema.Severity_Ubuntu || sev.GetType() == osvschema.Severity_UNSPECIFIED) {
			return sev.GetScore() == "negligible"
		}
	}

	for _, affected := range vuln.GetAffected() {
		if es := affected.GetEcosystemSpecific(); es != nil {
			if fields := es.GetFields(); fields != nil {
				if urgency, ok := fields["urgency"]; ok && urgency != nil {
					if urgency.GetStringValue() == "unimportant" {
						return true
					}
				}
				// TODO (gongh@): Remove this once Ubuntu has fully moved all priority tags into the severity field.
				if priority, ok := fields["ubuntu_priority"]; ok && priority != nil {
					if priority.GetStringValue() == "negligible" {
						return true
					}
				}
			}
		}
	}

	return false
}

func setUncalled(pkg models.PackageVulns, grouped []models.GroupInfo) {
	// Use index to keep reference to original element in slice
	for i := range grouped {
		for _, vulnID := range grouped[i].IDs {
			analysis := &grouped[i].ExperimentalAnalysis
			if *analysis == nil {
				*analysis = make(map[string]models.AnalysisInfo)
			}

			isUncalled := false

			for _, e := range pkg.Package.Inventory.ExploitabilitySignals {
				if e.Justification == vex.VulnerableCodeNotInExecutePath {
					isUncalled = true
					break
				}
			}

			(*analysis)[vulnID] = models.AnalysisInfo{
				Called:      !isUncalled,
				Unimportant: (*analysis)[vulnID].Unimportant,
			}
		}
	}
}
