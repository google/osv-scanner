package client

import (
	"sync"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/resolution/util"
	"github.com/google/osv-scanner/internal/utility/vulns"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"golang.org/x/exp/maps"
)

type OSVClient struct {
	// vulnCache caches all vulnerabilities affecting any versions of particular packages.
	// We cache call vulns & manually check affected, rather than querying the affected versions directly
	// since remediation needs to query for OSV vulnerabilities multiple times for the same packages.
	vulnCache sync.Map // map[resolve.PackageKey][]models.Vulnerability
	// TODO: This tends to get the full info of a lot of vulns that never show up in the dependency graphs.
	// Worst case is something like PyPI:tensorflow, which has >600 vulns across all versions, but a specific version may be affected by 0.
}

func NewOSVClient() *OSVClient {
	return &OSVClient{}
}

func (c *OSVClient) FindVulns(g *resolve.Graph) ([]models.Vulnerabilities, error) {
	// Determine which packages we don't already have cached
	toQuery := make(map[resolve.PackageKey]struct{})
	for _, node := range g.Nodes[1:] { // skipping the root node
		pk := node.Version.PackageKey
		if _, ok := c.vulnCache.Load(pk); !ok {
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
					Ecosystem: string(util.OSVEcosystem[pk.System]),
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
			c.vulnCache.Store(pk, hydrated.Results[i].Vulns)
		}
	}

	// Compute the actual affected vulnerabilities for each node
	nodeVulns := make([]models.Vulnerabilities, len(g.Nodes))
	// For convenience, include the root node as an empty slice in the results
	for i, n := range g.Nodes {
		if i == 0 {
			continue
		}
		pkgVulnsAny, ok := c.vulnCache.Load(n.Version.PackageKey)
		if !ok {
			// This should be impossible
			panic("vulnerability caching failed")
		}
		pkgVulns, ok := pkgVulnsAny.([]models.Vulnerability)
		if !ok {
			panic("vulnerability caching failed")
		}

		var affectedVulns []models.Vulnerability
		pkgDetails := util.VKToPackageDetails(n.Version)
		for _, vuln := range pkgVulns {
			if vulns.IsAffected(vuln, pkgDetails) {
				affectedVulns = append(affectedVulns, vuln)
			}
		}
		nodeVulns[i] = affectedVulns
	}

	return nodeVulns, nil
}
