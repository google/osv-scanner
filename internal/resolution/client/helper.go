package client

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// GraphAsInventory is a helper function to convert a Graph into an Inventory for use with VulnerabilityMatcher.
func GraphAsInventory(g *resolve.Graph) []*extractor.Inventory {
	// g.Nodes[0] is the root node of the graph that should be excluded.
	inv := make([]*extractor.Inventory, len(g.Nodes)-1)
	for i, n := range g.Nodes[1:] {
		inv[i] = &extractor.Inventory{
			Name:      n.Version.Name,
			Version:   n.Version.Version,
			Extractor: mockExtractor{n.Version.System},
		}
	}

	return inv
}

// mockExtractor is for GraphAsInventory to get the ecosystem.
type mockExtractor struct {
	ecosystem resolve.System
}

func (e mockExtractor) Ecosystem(*extractor.Inventory) string {
	switch e.ecosystem {
	case resolve.NPM:
		return "npm"
	case resolve.Maven:
		return "Maven"
	case resolve.UnknownSystem:
		return ""
	default:
		return ""
	}
}

func (e mockExtractor) Name() string                                 { return "" }
func (e mockExtractor) Requirements() *plugin.Capabilities           { return nil }
func (e mockExtractor) ToPURL(*extractor.Inventory) *purl.PackageURL { return nil }
func (e mockExtractor) Version() int                                 { return 0 }
