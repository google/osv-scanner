// Package depgroups provides functionality for working with dependency groups.
//
// Deprecated: Use github.com/google/osv-scanner/v2/pkg/depgroups instead.
package depgroups

import (
	"github.com/google/osv-scanner/v2/pkg/depgroups"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
//
// Deprecated: Use github.com/google/osv-scanner/v2/pkg/depgroups.IsDevGroup instead.
func IsDevGroup(sys osvconstants.Ecosystem, groups []string) bool {
	return depgroups.IsDevGroup(sys, groups)
}
