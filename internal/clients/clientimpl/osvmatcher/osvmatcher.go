package osvmatcher

import (
	"context"
	"errors"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
	"osv.dev/bindings/go/osvdev"
	"osv.dev/bindings/go/osvdevexperimental"
)

const (
	maxConcurrentRequests = 1000
)

// OSVMatcher implements the VulnerabilityMatcher interface with an osv.dev client.
// It sends out requests for every package version and does not perform caching.
type OSVMatcher struct {
	Client osvdev.OSVClient
	// InitialQueryTimeout allows you to set a timeout specifically for the initial paging query
	// If timeout runs out, whatever pages that has been successfully queried within the timeout will
	// still return fully hydrated.
	InitialQueryTimeout time.Duration
}

func New(initialQueryTimeout time.Duration, userAgent string) *OSVMatcher {
	client := *osvdev.DefaultClient()
	client.Config.UserAgent = userAgent

	return &OSVMatcher{
		Client:              client,
		InitialQueryTimeout: initialQueryTimeout,
	}
}

// MatchVulnerabilities matches vulnerabilities for a list of packages.
func (matcher *OSVMatcher) MatchVulnerabilities(ctx context.Context, pkgs []*extractor.Package) ([][]*osvschema.Vulnerability, error) {
	var batchResp *osvdev.BatchedResponse
	deadlineExceeded := false

	{
		var err error

		// convert Package to Query for each pkgs element
		queries := invsToQueries(pkgs)
		// If there is a timeout for the initial query, set an additional context deadline here.
		if matcher.InitialQueryTimeout > 0 {
			batchQueryCtx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(matcher.InitialQueryTimeout))
			batchResp, err = osvdevexperimental.BatchQueryPaging(batchQueryCtx, &matcher.Client, queries)
			cancelFunc()
		} else {
			batchResp, err = osvdevexperimental.BatchQueryPaging(ctx, &matcher.Client, queries)
		}

		if err != nil {
			// Deadline being exceeded is likely caused by a long paging time
			// if that's the case, we should return what we already got, and
			// then let the caller know it is not all the results.
			if errors.Is(err, context.DeadlineExceeded) {
				deadlineExceeded = true
			} else {
				return nil, err
			}
		}

		// No results found - this could be due to a timeout
		if batchResp == nil {
			return nil, err
		}
	}

	vulnerabilities := make([][]*osvschema.Vulnerability, len(batchResp.Results))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.Results {
		vulnerabilities[batchIdx] = make([]*osvschema.Vulnerability, len(resp.Vulns))
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

func pkgToQuery(pkg imodels.PackageInfo) *osvdev.Query {
	if pkg.Name() != "" && !pkg.Ecosystem().IsEmpty() && pkg.Version() != "" {
		return &osvdev.Query{
			Package: osvdev.Package{
				Name:      pkg.Name(),
				Ecosystem: pkg.Ecosystem().String(),
			},
			Version: pkg.Version(),
		}
	}

	if pkg.Commit() != "" {
		return &osvdev.Query{
			Commit: pkg.Commit(),
		}
	}

	// This should have be filtered out before reaching this point
	cmdlogger.Errorf("invalid query element: %#v", pkg)

	return nil
}

// invsToQueries converts inventories to queries via the osv-scanner internal imodels
// to perform the necessary transformations
func invsToQueries(invs []*extractor.Package) []*osvdev.Query {
	queries := make([]*osvdev.Query, len(invs))

	for i, inv := range invs {
		pkg := imodels.FromInventory(inv)
		queries[i] = pkgToQuery(pkg)
	}

	return queries
}
