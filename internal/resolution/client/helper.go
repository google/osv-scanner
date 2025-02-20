package client

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/resolution/util"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/ecosystemmock"
)

// GraphToInventory is a helper function to convert a Graph into an Inventory for use with VulnerabilityMatcher.
func GraphToInventory(g *resolve.Graph) []*extractor.Inventory {
	// g.Nodes[0] is the root node of the graph that should be excluded.
	inv := make([]*extractor.Inventory, len(g.Nodes)-1)
	for i, n := range g.Nodes[1:] {
		inv[i] = &extractor.Inventory{
			Name:    n.Version.Name,
			Version: n.Version.Version,
			Extractor: ecosystemmock.Extractor{
				MockEcosystem: string(util.OSVEcosystem[n.Version.System]),
			},
		}
	}

	return inv
}
