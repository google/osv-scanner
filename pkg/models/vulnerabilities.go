package models

import (
	"encoding/json"
	"fmt"
)

type Vulnerabilities []Vulnerability

func (vs Vulnerabilities) Includes(vulnerability Vulnerability) bool {
	for _, vuln := range vs {
		if vuln.ID == vulnerability.ID {
			return true
		}

		if vuln.isAliasOf(vulnerability) {
			return true
		}
		if vulnerability.isAliasOf(vuln) {
			return true
		}
	}

	return false
}

// MarshalJSON ensures that if there are no vulnerabilities,
// an empty array is used as the value instead of "null"
func (vs Vulnerabilities) MarshalJSON() ([]byte, error) {
	if len(vs) == 0 {
		return []byte("[]"), nil
	}

	type innerVulnerabilities Vulnerabilities

	out, err := json.Marshal(innerVulnerabilities(vs))

	if err != nil {
		return out, fmt.Errorf("%w", err)
	}

	return out, nil
}
