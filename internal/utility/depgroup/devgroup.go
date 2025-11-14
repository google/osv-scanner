// Package depgroups provides functionality for working with dependency groups.
package depgroups

import (
	"slices"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
func IsDevGroup(sys osvconstants.Ecosystem, groups []string) bool {
	var dev string
	switch sys {
	case osvconstants.EcosystemPackagist, osvconstants.EcosystemNPM, osvconstants.EcosystemPyPI, osvconstants.EcosystemPub:
		dev = "dev"
	case osvconstants.EcosystemConanCenter:
		dev = "build-requires"
	case osvconstants.EcosystemMaven:
		dev = "test"
	default:
		// We are not able to report development dependencies for these ecosystems.
		return false
	}

	return slices.Contains(groups, dev)
}
