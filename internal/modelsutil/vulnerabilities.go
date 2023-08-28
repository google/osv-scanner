package modelsutil

import "github.com/google/osv-scanner/pkg/models"

func VulnsInclude(vs models.Vulnerabilities, vulnerability models.Vulnerability) bool {
	for _, vuln := range vs {
		if vuln.ID == vulnerability.ID {
			return true
		}

		if vulnIsAliasOf(vuln, vulnerability) {
			return true
		}
		if vulnIsAliasOf(vulnerability, vuln) {
			return true
		}
	}

	return false
}
