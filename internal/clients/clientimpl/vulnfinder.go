package clientimpl

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/internal/osvdev"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/sync/errgroup"
)

const (
	maxConcurrentRequests = 1000
)

type VulnFinder struct {
	Client osvdev.OSVClient
}

func (vf *VulnFinder) Match(ctx context.Context, pkgs []*extractor.Inventory) ([][]*models.Vulnerability, error) {
	// convert Package to Query for each pkgs element
	queries := pkgToQueries(pkgs)
	batchResp, err := vf.Client.QueryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	// TODO: Paging
	vulnerabilities := make([][]*models.Vulnerability, len(batchResp.Results))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.Results {
		vulnerabilities[batchIdx] = make([]*models.Vulnerability, len(resp.Vulns))
		for resultIdx, vuln := range resp.Vulns {
			g.Go(func() error {
				// exit early if another hydration request has already failed
				// results are thrown away later, so avoid needless work
				if ctx.Err() != nil {
					return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
				}
				vuln, err := vf.Client.GetVulnsByID(ctx, vuln.ID)
				if err != nil {
					return err
				}
				vulnerabilities[batchIdx][resultIdx] = vuln

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return vulnerabilities, nil
}

func pkgToQueries(invs []*extractor.Inventory) []*osvdev.Query {
	queries := make([]*osvdev.Query, len(invs))
	for i, inv := range invs {
		if inv.SourceCode != nil && inv.SourceCode.Commit != "" {
			queries[i] = &osvdev.Query{
				Commit: inv.SourceCode.Commit,
			}
			continue
		}

		queries[i] = &osvdev.Query{
			Package: osvdev.Package{
				Name:      inv.Name,
				Ecosystem: inv.Ecosystem(),
			},
			Version: inv.Version,
		}
	}

	return queries
}
