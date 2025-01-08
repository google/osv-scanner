package client

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// GraphAsInventory is a helper function to convert a Graph into an Inventory for use with VulnerabilityMatcher.
func GraphAsInventory(g *resolve.Graph) []*extractor.Inventory {
	// g.Nodes[0] is the root node of the graph that should be excluded.
	inv := make([]*extractor.Inventory, len(g.Nodes)-1)
	for i, n := range g.Nodes[1:] {
		inv[i] = &extractor.Inventory{
			Name:      n.Version.Name,
			Version:   n.Version.Version,
			Metadata:  n,
			Extractor: graphExtractor{},
			Locations: []string{g.Nodes[0].Version.Name},
		}
	}
	return inv
}

// graphExtractor is for GraphAsInventory to get the ecosystem.
type graphExtractor struct{}

func (e graphExtractor) Ecosystem(i *extractor.Inventory) string {
	n, ok := i.Metadata.(resolve.Node)
	if !ok {
		return ""
	}
	switch n.Version.System {
	case resolve.NPM:
		return string(osvschema.EcosystemNPM)
	case resolve.Maven:
		return string(osvschema.EcosystemMaven)
	default:
		return ""
	}
}

func (e graphExtractor) Name() string                                   { return "" }
func (e graphExtractor) Requirements() *plugin.Capabilities             { return nil }
func (e graphExtractor) ToPURL(_ *extractor.Inventory) *purl.PackageURL { return nil }
func (e graphExtractor) Version() int                                   { return 0 }
