package vulns

import "github.com/google/osv-scanner/pkg/models"

func Include(vs models.Vulnerabilities, vulnerability models.Vulnerability) bool {
	for _, vuln := range vs {
		if vuln.ID == vulnerability.ID {
			return true
		}

		if isAliasOf(vuln, vulnerability) {
			return true
		}
		if isAliasOf(vulnerability, vuln) {
			return true
		}
	}

	return false
}
