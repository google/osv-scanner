// Package depgroups provides functionality for working with dependency groups.
package depgroups

import (
	"slices"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
func IsDevGroup(sys osvschema.Ecosystem, groups []string) bool {
	var dev string
	switch sys {
	case osvschema.EcosystemPackagist, osvschema.EcosystemNPM, osvschema.EcosystemPyPI, osvschema.EcosystemPub:
		dev = "dev"
	case osvschema.EcosystemConanCenter:
		dev = "build-requires"
	case osvschema.EcosystemMaven:
		dev = "test"
	default:
		// We are not able to report development dependencies for these ecosystems.
		return false
	}

	return slices.Contains(groups, dev)
}
