package client

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/resolution/util"
)

// GraphToInventory is a helper function to convert a Graph into an Package for use with VulnerabilityMatcher.
func GraphToInventory(g *resolve.Graph) []*extractor.Package {
	// g.Nodes[0] is the root node of the graph that should be excluded.
	inv := make([]*extractor.Package, len(g.Nodes)-1)
	for i, n := range g.Nodes[1:] {
		inv[i] = &extractor.Package{
			Name:     n.Version.Name,
			Version:  n.Version.Version,
			PURLType: util.PURLType[n.Version.System],
		}
	}

	return inv
}
