package spdx

import "strings"

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
