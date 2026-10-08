package grouper

import (
	"fmt"

	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
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

func Build(pkg models.PackageVulns) []models.GroupInfo {
	grouped := Group(ConvertVulnerabilityToIDAliases(pkg.Vulnerabilities))
	for i, group := range grouped {
		grouped[i].MaxSeverity = calculateMaxSeverity(group, pkg)
	}

	return grouped
}
