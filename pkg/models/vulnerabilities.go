package models

import (
	"encoding/json"
	"fmt"
)

type Vulnerabilities []Vulnerability

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
