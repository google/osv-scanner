package spdx

import (
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// IsSPDX reports whether the given license string is a recognized SPDX identifier.
func IsSPDX(license string) bool {
	return IDs[strings.ToLower(license)]
}

// IsExpression reports whether the given license string is an SPDX compound expression.
func IsExpression(license string) bool {
	ts := tokenise(models.License(license))
	for _, t := range ts.tokens {
		if t == "AND" || t == "OR" || t == "WITH" {
			return true
		}
	}

	return false
}

// Unrecognized filters licenses for non-spdx identifiers. The "unknown" string is
// also treated as a valid identifier.
func Unrecognized(licenses []string) (unrecognized []string) {
	for _, license := range licenses {
		l := strings.ToLower(license)
		if !IDs[l] && l != "unknown" {
			unrecognized = append(unrecognized, license)
		}
	}

	return unrecognized
}
