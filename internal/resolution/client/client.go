package client

import (
	"context"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/pkg/models"
)

type ResolutionClient struct {
	DependencyClient
	VulnerabilityClient
}

type DependencyClient interface {
	resolve.Client
	// WriteCache writes a manifest-specific resolution cache.
	WriteCache(filepath string) error
	// LoadCache loads a manifest-specific resolution cache.
	LoadCache(filepath string) error
	// PreFetch loads cache, then makes and caches likely queries needed for resolving a package with a list of requirements
	PreFetch(ctx context.Context, requirements []resolve.RequirementVersion, manifestPath string)
}

type VulnerabilityClient interface {
	// FindVulns finds the vulnerabilities affecting each of Nodes in the graph.
	// The returned Vulnerabilities[i] corresponds to the vulnerabilities in g.Nodes[i].
	FindVulns(g *resolve.Graph) ([]models.Vulnerabilities, error)
}
