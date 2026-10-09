package grouper

import (
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func Build(pkg models.PackageVulns) []models.GroupInfo {
	grouped := Group(ConvertVulnerabilityToIDAliases(pkg.Vulnerabilities))
	for i, group := range grouped {
		grouped[i].MaxSeverity = output.MaxSeverity(group, pkg)
	}

	return grouped
}
