package vulns

import "github.com/google/osv-scanner/v2/pkg/models"

func Include(vs []*models.Vulnerability, vulnerability models.Vulnerability) bool {
	for _, vuln := range vs {
		if vuln.ID == vulnerability.ID {
			return true
		}

		if isAliasOf(*vuln, vulnerability) {
			return true
		}
		if isAliasOf(vulnerability, *vuln) {
			return true
		}
	}

	return false
}
