// Package osvmatcher implements two vulnerability matcher using osv.dev's API.
package osvmatcher

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
	"osv.dev/bindings/go/osvdev"
	"osv.dev/bindings/go/osvdevexperimental"
)

// CachedOSVMatcher implements the VulnerabilityMatcher interface with a osv.dev client.
// It sends out requests for every vulnerability of each package, which get cached.
// Checking if a specific version matches an OSV record is done locally.
// This should be used when we know the same packages are going to be repeatedly
// queried multiple times, as in guided remediation.
// TODO: This does not support commit-based queries.
type CachedOSVMatcher struct {
	Client osvdev.OSVClient
	// InitialQueryTimeout allows you to set a timeout specifically for the initial paging query
	// If timeout runs out, whatever pages that has been successfully queried within the timeout will
	// still return fully hydrated.
	InitialQueryTimeout time.Duration

	vulnCache sync.Map // map[osvdev.Package][]osvschema.Vulnerability
}

func (matcher *CachedOSVMatcher) MatchVulnerabilities(ctx context.Context, invs []*extractor.Package) ([][]*osvschema.Vulnerability, error) {
	// populate vulnCache with missing packages
	if err := matcher.doQueries(ctx, invs); err != nil {
		return nil, err
	}

	results := make([][]*osvschema.Vulnerability, len(invs))

	for i, inv := range invs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkgInfo := imodels.FromInventory(inv)
		pkg := osvdev.Package{
			Name:      pkgInfo.Name(),
			Ecosystem: pkgInfo.Ecosystem().String(),
		}
		vulns, ok := matcher.vulnCache.Load(pkg)
		if !ok {
			continue
		}
		results[i] = localmatcher.VulnerabilitiesAffectingPackage(vulns.([]osvschema.Vulnerability), pkgInfo)
	}

	return results, nil
}

func (matcher *CachedOSVMatcher) doQueries(ctx context.Context, invs []*extractor.Package) error {
	var batchResp *osvdev.BatchedResponse
	deadlineExceeded := false

	var queries []*osvdev.Query
	{
		// determine which packages aren't already cached
		// convert Package to Query for each pkgs element
		toQuery := make(map[*osvdev.Query]struct{})
		for _, inv := range invs {
			pkgInfo := imodels.FromInventory(inv)
			if pkgInfo.Name() == "" || pkgInfo.Ecosystem().IsEmpty() {
				continue
			}
			pkg := osvdev.Package{
				Name:      pkgInfo.Name(),
				Ecosystem: pkgInfo.Ecosystem().String(),
			}
			if _, ok := matcher.vulnCache.Load(pkg); !ok {
				toQuery[&osvdev.Query{Package: pkg}] = struct{}{}
			}
		}
		queries = slices.AppendSeq(make([]*osvdev.Query, 0, len(toQuery)), maps.Keys(toQuery))
	}

	if len(queries) == 0 {
		return nil
	}

	var err error

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
			return err
		}
	}

	vulnerabilities := make([][]osvschema.Vulnerability, len(batchResp.Results))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.Results {
		vulnerabilities[batchIdx] = make([]osvschema.Vulnerability, len(resp.Vulns))
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
				vulnerabilities[batchIdx][resultIdx] = *vuln

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return err
	}

	if deadlineExceeded {
		return context.DeadlineExceeded
	}

	for i, vulns := range vulnerabilities {
		matcher.vulnCache.Store(queries[i].Package, vulns)
	}

	return nil
}
