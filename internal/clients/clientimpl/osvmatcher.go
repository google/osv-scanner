package clientimpl

import (
	"context"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/osvdev"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/sync/errgroup"
)

const (
	maxConcurrentRequests = 1000
)

type OSVMatcher struct {
	Client osvdev.OSVClient
	// InitialQueryTimeout allows you to set a timeout specifically for the initial paging query
	// If timeout runs out, whatever pages that has been successfully queried within the timeout will
	// still return fully hydrated.
	InitialQueryTimeout time.Duration
}

func (vf *OSVMatcher) Match(ctx context.Context, pkgs []*extractor.Inventory) ([][]models.Vulnerability, error) {
	var batchResp *osvdev.BatchedResponse
	deadlineExceeded := false

	{
		var err error

		// convert Inventory to Query for each pkgs element
		queries := invsToQueries(pkgs)
		// If there is a timeout for the initial query, set an additional context deadline here.
		if vf.InitialQueryTimeout > 0 {
			batchQueryCtx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(vf.InitialQueryTimeout))
			batchResp, err = vf.Client.QueryBatch(batchQueryCtx, queries)
			cancelFunc()
		} else {
			batchResp, err = vf.Client.QueryBatch(ctx, queries)
		}
		if err != nil {
			if err == context.DeadlineExceeded {
				deadlineExceeded = true
			} else {
				return nil, err
			}
		}
	}

	vulnerabilities := make([][]models.Vulnerability, len(batchResp.Results))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.Results {
		vulnerabilities[batchIdx] = make([]models.Vulnerability, len(resp.Vulns))
		for resultIdx, vuln := range resp.Vulns {
			g.Go(func() error {
				// exit early if another hydration request has already failed
				// results are thrown away later, so avoid needless work
				if ctx.Err() != nil {
					return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
				}
				vuln, err := vf.Client.GetVulnByID(ctx, vuln.ID)
				if err != nil {
					return err
				}
				vulnerabilities[batchIdx][resultIdx] = *vuln

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	if deadlineExceeded {
		return vulnerabilities, context.DeadlineExceeded
	} else {
		return vulnerabilities, nil
	}
}

func pkgToQuery(pkg imodels.PackageInfo) *osvdev.Query {
	if pkg.Name != "" && !pkg.Ecosystem.IsEmpty() && pkg.Version != "" {
		return &osvdev.Query{
			Package: osvdev.Package{
				Name:      pkg.Name,
				Ecosystem: pkg.Ecosystem.String(),
			},
			Version: pkg.Version,
		}
	}

	if pkg.Commit != "" {
		return &osvdev.Query{
			Commit: pkg.Commit,
		}
	}

	// This should have be filtered out before reaching this point
	log.Errorf("invalid query element: %#v", pkg)
	return nil
}

// invsToQueries converts inventories to queries via the osv-scanner internal imodels
// to perform the necessary transformations
func invsToQueries(invs []*extractor.Inventory) []*osvdev.Query {
	queries := make([]*osvdev.Query, len(invs))

	for i, inv := range invs {
		queries[i] = pkgToQuery(imodels.FromInventory(inv))
	}

	return queries
}
