package spdx

import (
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

// Satisfies checks if the given license expression is satisfied by the allowed licenses
func Satisfies(license models.License, allowlist []string) bool {
	lowerLicense := strings.ToLower(string(license))

	for _, l := range allowlist {
		if lowerLicense == strings.ToLower(l) {
			return true
		}
	}

	return false
}
