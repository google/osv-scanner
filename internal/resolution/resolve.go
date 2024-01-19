package resolution

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/npm"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

type ResolutionVuln struct {
	Vulnerability models.Vulnerability
	DevOnly       bool
	// Chains are paths through requirements from direct dependency to vulnerable package.
	// A 'Problem' chain constrains the package to a vulnerable version.
	// 'NonProblem' chains re-use the vulnerable version, but would not resolve to a vulnerable version in isolation.
	ProblemChains    []DependencyChain
	NonProblemChains []DependencyChain
}

type ResolutionResult struct {
	Manifest        manifest.Manifest
	Graph           *resolve.Graph
	Vulns           []ResolutionVuln
	UnfilteredVulns []ResolutionVuln
}

func getResolver(sys resolve.System, cl resolve.Client) (resolve.Resolver, error) {
	switch sys { //nolint:exhaustive
	case resolve.NPM:
		return npm.NewResolver(cl), nil
	default:
		return nil, fmt.Errorf("no resolver for ecosystem %v", sys)
	}
}

func Resolve(ctx context.Context, cl resolve.Client, m manifest.Manifest) (*ResolutionResult, error) {
	c := client.NewOverrideClient(cl)
	c.AddVersion(m.Root, m.Requirements)
	for _, loc := range m.LocalManifests {
		c.AddVersion(loc.Root, loc.Requirements)
		// TODO: may need to do this recursively
	}
	r, err := getResolver(m.System(), c)
	if err != nil {
		return nil, err
	}

	graph, err := r.Resolve(ctx, m.Root.VersionKey)
	if err != nil {
		return nil, err
	}

	if len(graph.Error) > 0 {
		return nil, errors.New(graph.Error)
	}

	result := &ResolutionResult{
		Manifest: m.Clone(),
		Graph:    graph,
	}

	if err := result.computeVulns(ctx, c); err != nil {
		return nil, err
	}

	// Make a copy of the found vulns, as `Vulns` may be filtered according to specified criteria.
	result.UnfilteredVulns = slices.Clone(result.Vulns)

	return result, nil
}

var OSVEcosystem = map[resolve.System]models.Ecosystem{
	resolve.NPM:   models.EcosystemNPM,
	resolve.Maven: models.EcosystemMaven,
}

// computeVulns scans for vulnerabilities in a resolved graph and populates res.Vulns
func (res *ResolutionResult) computeVulns(ctx context.Context, cl resolve.Client) error {
	// TODO: local vulnerability db support
	// TODO: when remediating, this is going to get called many times for the same packages, we should cache requests to the OSV API
	// Find all vulnerability IDs affecting each node in the graph.
	var request osv.BatchedQuery
	request.Queries = make([]*osv.Query, len(res.Graph.Nodes)-1)
	for i, n := range res.Graph.Nodes[1:] { // skipping the root node
		request.Queries[i] = &osv.Query{
			Package: osv.Package{
				Name:      n.Version.Name,
				Ecosystem: string(OSVEcosystem[n.Version.System]),
			},
			Version: n.Version.Version,
		}
	}
	response, err := osv.MakeRequest(request)
	if err != nil {
		return err
	}
	nodeVulns := response.Results

	// Get the details for each vulnerability
	// To save on request size, hydrate only unique IDs
	vulnInfo := make(map[string]*models.Vulnerability)
	var hydrateQuery osv.BatchedResponse
	for _, vulns := range nodeVulns {
		for _, vuln := range vulns.Vulns {
			if _, ok := vulnInfo[vuln.ID]; !ok {
				vulnInfo[vuln.ID] = nil
				hydrateQuery.Results = append(hydrateQuery.Results, osv.MinimalResponse{Vulns: []osv.MinimalVulnerability{vuln}})
			}
		}
	}
	//nolint:contextcheck // TODO: Should Hydrate be accepting a context?
	hydrated, err := osv.Hydrate(&hydrateQuery)
	if err != nil {
		return err
	}

	for _, resp := range hydrated.Results {
		for _, vuln := range resp.Vulns {
			vuln := vuln
			vulnInfo[vuln.ID] = &vuln
		}
	}

	// Find all dependency paths to the vulnerable dependencies
	var vulnerableNodes []resolve.NodeID
	var vulnNodeIdxs []int
	for i, vulns := range nodeVulns {
		if len(vulns.Vulns) > 0 {
			vulnNodeIdxs = append(vulnNodeIdxs, i)
			vulnerableNodes = append(vulnerableNodes, resolve.NodeID(i+1))
		}
	}
	nodeChains := computeChains(res.Graph, vulnerableNodes)
	vulnChains := make(map[string][]DependencyChain)
	for i, idx := range vulnNodeIdxs {
		for _, vuln := range nodeVulns[idx].Vulns {
			vulnChains[vuln.ID] = append(vulnChains[vuln.ID], nodeChains[i]...)
		}
	}

	// construct the ResolutionVulns
	// TODO: This constructs a single ResolutionVuln per vulnerability ID.
	// The scan action treats vulns with the same ID but affecting different versions of a package as distinct.
	// TODO: Combine aliased IDs
	for id, vuln := range vulnInfo {
		rv := ResolutionVuln{Vulnerability: *vuln, DevOnly: true}
		for _, chain := range vulnChains[id] {
			if chainConstrains(ctx, cl, chain, vuln) {
				rv.ProblemChains = append(rv.ProblemChains, chain)
			} else {
				rv.NonProblemChains = append(rv.NonProblemChains, chain)
			}
			rv.DevOnly = rv.DevOnly && ChainIsDev(chain, res.Manifest)
		}
		res.Vulns = append(res.Vulns, rv)
	}

	return nil
}
