package resolution

import (
	"context"
	"sync"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/utility/vulns"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"golang.org/x/exp/maps"
)

// computeVulns scans for vulnerabilities in a resolved graph and populates res.Vulns
func (res *ResolutionResult) computeVulns(ctx context.Context, cl resolve.Client) error {
	// TODO: local vulnerability db support

	//nolint:contextcheck // TODO: Should Hydrate be accepting a context?
	nodeVulns, err := queryOSV(res.Graph)
	if err != nil {
		return err
	}
	// Find all dependency paths to the vulnerable dependencies
	var vulnerableNodes []resolve.NodeID
	vulnInfo := make(map[string]models.Vulnerability)
	for i, vulns := range nodeVulns {
		if len(vulns) > 0 {
			vulnerableNodes = append(vulnerableNodes, resolve.NodeID(i))
		}
		for _, vuln := range vulns {
			vulnInfo[vuln.ID] = vuln
		}
	}

	nodeChains := computeChains(res.Graph, vulnerableNodes)
	vulnChains := make(map[string][]DependencyChain)
	for i, idx := range vulnerableNodes {
		for _, vuln := range nodeVulns[idx] {
			vulnChains[vuln.ID] = append(vulnChains[vuln.ID], nodeChains[i]...)
		}
	}

	// construct the ResolutionVulns
	// TODO: This constructs a single ResolutionVuln per vulnerability ID.
	// The scan action treats vulns with the same ID but affecting different versions of a package as distinct.
	// TODO: Combine aliased IDs
	for id, vuln := range vulnInfo {
		rv := ResolutionVuln{Vulnerability: vuln, DevOnly: true}
		for _, chain := range vulnChains[id] {
			if chainConstrains(ctx, cl, chain, &rv.Vulnerability) {
				rv.ProblemChains = append(rv.ProblemChains, chain)
			} else {
				rv.NonProblemChains = append(rv.NonProblemChains, chain)
			}
			rv.DevOnly = rv.DevOnly && ChainIsDev(chain, res.Manifest)
		}
		if len(rv.ProblemChains) == 0 {
			// There has to be at least one problem chain for the vulnerability to appear.
			// If our heuristic couldn't determine any, treat them all as problematic.
			rv.ProblemChains = rv.NonProblemChains
			rv.NonProblemChains = nil
		}
		res.Vulns = append(res.Vulns, rv)
	}

	return nil
}

// vulnCache caches all vulnerabilities affecting any versions of particular packages.
// We cache call vulns & manually check affected, rather than querying the affected versions directly
// since remediation needs to query for OSV vulnerabilities multiple times for the same packages.
var vulnCache sync.Map // map[resolve.PackageKey][]models.Vulnerability
// TODO: This tends to get the full info of a lot of vulns that never show up in the dependency graphs.
// Worst case is something like PyPI:tensorflow, which has >600 vulns across all versions, but a specific version may be affected by 0.

func queryOSV(g *resolve.Graph) ([][]models.Vulnerability, error) {
	// Determine which packages we don't already have cached
	toQuery := make(map[resolve.PackageKey]struct{})
	for _, node := range g.Nodes[1:] { // skipping the root node
		pk := node.Version.PackageKey
		if _, ok := vulnCache.Load(pk); !ok {
			toQuery[pk] = struct{}{}
		}
	}

	// Query OSV for the missing records
	if len(toQuery) > 0 {
		pks := maps.Keys(toQuery)
		var batchRequest osv.BatchedQuery
		batchRequest.Queries = make([]*osv.Query, len(pks))
		for i, pk := range pks {
			batchRequest.Queries[i] = &osv.Query{
				Package: osv.Package{
					Name:      pk.Name,
					Ecosystem: string(OSVEcosystem[pk.System]),
				},
				// Omitting the Version from the query gets all vulns affecting any version of the package
				// (I'm not actually sure if this behaviour is explicitly documented anywhere)
			}
		}
		batchResponse, err := osv.MakeRequest(batchRequest)
		if err != nil {
			return nil, err
		}
		hydrated, err := osv.Hydrate(batchResponse)
		if err != nil {
			return nil, err
		}
		// fill in the cache with the responses
		for i, pk := range pks {
			vulnCache.Store(pk, hydrated.Results[i].Vulns)
		}
	}

	// Compute the actual affected vulnerabilities for each node
	nodeVulns := make([][]models.Vulnerability, len(g.Nodes))
	// For convenience, include the root node as an empty slice in the results
	for i, n := range g.Nodes {
		if i == 0 {
			continue
		}
		pkgVulnsAny, ok := vulnCache.Load(n.Version.PackageKey)
		if !ok {
			// This should be impossible
			panic("vulnerability caching failed")
		}
		pkgVulns, ok := pkgVulnsAny.([]models.Vulnerability)
		if !ok {
			panic("vulnerability caching failed")
		}

		var affectedVulns []models.Vulnerability
		pkgDetails := lockfile.PackageDetails{
			Name:      n.Version.Name,
			Version:   n.Version.Version,
			Ecosystem: lockfile.Ecosystem(OSVEcosystem[n.Version.System]),
			CompareAs: lockfile.Ecosystem(OSVEcosystem[n.Version.System]),
		}
		for _, vuln := range pkgVulns {
			if vulns.IsAffected(vuln, pkgDetails) {
				affectedVulns = append(affectedVulns, vuln)
			}
		}
		nodeVulns[i] = affectedVulns
	}

	return nodeVulns, nil
}
