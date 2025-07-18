// Package vulns provides utility functions for working with vulnerabilities.
package vulns

import "github.com/ossf/osv-schema/bindings/go/osvschema"

func Include(vs []*osvschema.Vulnerability, vulnerability osvschema.Vulnerability) bool {
	for _, vuln := range vs {
		if vuln.ID == vulnerability.ID {
			return true
		}
	}

	return false
}
