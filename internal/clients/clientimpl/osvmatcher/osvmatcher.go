package osvmatcher

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/osvdev"
	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
)

const (
	maxConcurrentRequests = 1000
)

// OSVMatcher implements the VulnerabilityMatcher interface with a osv.dev client.
// It sends out requests for every package version and does not perform caching.
type OSVMatcher struct {
	Client osvdev.OSVClient
	// InitialQueryTimeout allows you to set a timeout specifically for the initial paging query
	// If timeout runs out, whatever pages that has been successfully queried within the timeout will
	// still return fully hydrated.
	InitialQueryTimeout time.Duration
}

func (matcher *OSVMatcher) Match(ctx context.Context, pkgs []*extractor.Inventory) ([][]*models.Vulnerability, error) {
	var batchResp *osvdev.BatchedResponse
	deadlineExceeded := false

	{
		var err error

		// convert Inventory to Query for each pkgs element
		queries := invsToQueries(pkgs)
		// If there is a timeout for the initial query, set an additional context deadline here.
		if matcher.InitialQueryTimeout > 0 {
			batchQueryCtx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(matcher.InitialQueryTimeout))
			batchResp, err = queryForBatchWithPaging(batchQueryCtx, &matcher.Client, queries)
			cancelFunc()
		} else {
			batchResp, err = queryForBatchWithPaging(ctx, &matcher.Client, queries)
		}

		if err != nil {
			// Deadline being exceeded is likely caused by a long paging time
			// if that's the case, we can should return what we already got, and
			// then let the caller know it is not all the results.
			if errors.Is(err, context.DeadlineExceeded) {
				deadlineExceeded = true
			} else {
				return nil, err
			}
		}
	}

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
				vuln, err := matcher.Client.GetVulnByID(ctx, vuln.ID)
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

	if deadlineExceeded {
		return vulnerabilities, context.DeadlineExceeded
	}

	return vulnerabilities, nil
}

func queryForBatchWithPaging(ctx context.Context, c *osvdev.OSVClient, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	batchResp, err := c.QueryBatch(ctx, queries)

	if err != nil {
		return nil, err
	}
	// --- Paging logic ---
	var errToReturn error
	nextPageQueries := []*osvdev.Query{}
	nextPageIndexMap := []int{}
	for i, res := range batchResp.Results {
		if res.NextPageToken == "" {
			continue
		}

		query := *queries[i]
		query.PageToken = res.NextPageToken
		nextPageQueries = append(nextPageQueries, &query)
		nextPageIndexMap = append(nextPageIndexMap, i)
	}

	if len(nextPageQueries) > 0 {
		// If context is cancelled or deadline exceeded, return now
		if ctx.Err() != nil {
			return batchResp, &DuringPagingError{
				PageDepth: 1,
				Inner:     ctx.Err(),
			}
		}

		nextPageResp, err := c.QueryBatch(ctx, nextPageQueries)
		if err != nil {
			var dpr *DuringPagingError
			if ok := errors.As(err, &dpr); ok {
				dpr.PageDepth += 1
				errToReturn = dpr
			} else {
				errToReturn = &DuringPagingError{
					PageDepth: 1,
					Inner:     err,
				}
			}
		}

		// Whether there is an error or not, if there is any data,
		// we want to save and return what we got.
		if nextPageResp != nil {
			for i, res := range nextPageResp.Results {
				batchResp.Results[nextPageIndexMap[i]].Vulns = append(batchResp.Results[nextPageIndexMap[i]].Vulns, res.Vulns...)
				// Set next page token so caller knows whether this is all of the results
				// even if it is being cancelled.
				batchResp.Results[nextPageIndexMap[i]].NextPageToken = res.NextPageToken
			}
		}
	}

	return batchResp, errToReturn
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
		pkg := imodels.FromInventory(inv)
		pkg = patchPackageForRequest(pkg)
		queries[i] = pkgToQuery(pkg)
	}

	return queries
}

// patchPackageForRequest modifies packages before they are sent to osv.dev to
// account for edge cases.
func patchPackageForRequest(pkg imodels.PackageInfo) imodels.PackageInfo {
	// Assume Go stdlib patch version as the latest version
	//
	// This is done because go1.20 and earlier do not support patch
	// version in go.mod file, and will fail to build.
	//
	// However, if we assume patch version as .0, this will cause a lot of
	// false positives. This compromise still allows osv-scanner to pick up
	// when the user is using a minor version that is out-of-support.
	if pkg.Name == "stdlib" && pkg.Ecosystem.Ecosystem == osvschema.EcosystemGo {
		v := semantic.ParseSemverLikeVersion(pkg.Version, 3)
		if len(v.Components) == 2 {
			pkg.Version = fmt.Sprintf(
				"%d.%d.%d",
				v.Components.Fetch(0),
				v.Components.Fetch(1),
				9999,
			)
		}
	}

	return pkg
}
