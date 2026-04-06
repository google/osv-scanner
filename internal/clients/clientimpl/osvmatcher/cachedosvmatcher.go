package osvmatcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/semantic"
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
// queried multiple times, as in guided remediation. Commit-based queries are
// passed through directly without caching.
type CachedOSVMatcher struct {
	Client osvdev.OSVClient
	// InitialQueryTimeout allows you to set a timeout specifically for the initial paging query
	// If timeout runs out, whatever pages that has been successfully queried within the timeout will
	// still return fully hydrated.
	InitialQueryTimeout time.Duration

	vulnCache sync.Map // map[osvdev.Package][]osvschema.Vulnerability
}

type cachedQueryPlan struct {
	queries              []*osvdev.Query
	cacheHits            int
	duplicateSuppressed  int
	repeatedPackageLines []string
}

type batchQueryMetrics struct {
	queryBatchRequests int
	vulnDetailRequests int
}

type directQueryResult struct {
	vulnerabilities []*osvschema.Vulnerability
}

func batchQueryPagingWithMetrics(ctx context.Context, c *osvdev.OSVClient, queries []*osvdev.Query, metrics *batchQueryMetrics) (*osvdev.BatchedResponse, error) {
	metrics.queryBatchRequests++
	batchResp, err := c.QueryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	var errToReturn error
	var nextPageQueries []*osvdev.Query
	var nextPageIndexMap []int
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
		if ctx.Err() != nil {
			return batchResp, &osvdevexperimental.DuringPagingError{
				PageDepth: 1,
				Inner:     ctx.Err(),
			}
		}

		nextPageResp, err := batchQueryPagingWithMetrics(ctx, c, nextPageQueries, metrics)
		if err != nil {
			var dpe *osvdevexperimental.DuringPagingError
			if ok := errors.As(err, &dpe); ok {
				dpe.PageDepth += 1
				errToReturn = dpe
			} else {
				errToReturn = &osvdevexperimental.DuringPagingError{
					PageDepth: 1,
					Inner:     err,
				}
			}
		}

		if nextPageResp != nil {
			for i, res := range nextPageResp.Results {
				batchResp.Results[nextPageIndexMap[i]].Vulns = append(batchResp.Results[nextPageIndexMap[i]].Vulns, res.Vulns...)
				batchResp.Results[nextPageIndexMap[i]].NextPageToken = res.NextPageToken
			}
		}
	}

	return batchResp, errToReturn
}

func (matcher *CachedOSVMatcher) MatchVulnerabilities(ctx context.Context, invs []*extractor.Package) ([][]*osvschema.Vulnerability, error) {
	results := make([][]*osvschema.Vulnerability, len(invs))

	packageInvs := make([]*extractor.Package, 0, len(invs))
	passthroughInvs := make([]*extractor.Package, 0)
	passthroughIndexes := make([]int, 0)
	for i, inv := range invs {
		pkgInfo := imodels.FromInventory(inv)
		switch {
		case shouldUseCachedPackageQuery(pkgInfo):
			packageInvs = append(packageInvs, inv)
		case pkgInfo.Commit() != "" || (pkgInfo.Name() != "" && !pkgInfo.Ecosystem().IsEmpty()):
			passthroughInvs = append(passthroughInvs, inv)
			passthroughIndexes = append(passthroughIndexes, i)
		}
	}

	plan, queryMetrics, err := matcher.doQueries(ctx, packageInvs)
	if err != nil {
		return nil, err
	}

	for i, inv := range invs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkgInfo := imodels.FromInventory(inv)
		if pkgInfo.Name() == "" || pkgInfo.Ecosystem().IsEmpty() {
			continue
		}
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

	passthroughResults, passthroughMetrics, err := matcher.matchDirectQueries(ctx, passthroughInvs)
	if err != nil {
		return nil, err
	}
	queryMetrics.queryBatchRequests += passthroughMetrics.queryBatchRequests
	queryMetrics.vulnDetailRequests += passthroughMetrics.vulnDetailRequests
	for i, res := range passthroughResults {
		results[passthroughIndexes[i]] = res.vulnerabilities
	}

	matcher.logSummary(len(invs), plan, queryMetrics)

	return results, nil
}

func (matcher *CachedOSVMatcher) buildQueryPlan(invs []*extractor.Package) cachedQueryPlan {
	plan := cachedQueryPlan{}
	toQuery := make(map[osvdev.Package]struct{})
	occurrenceCounts := make(map[osvdev.Package]int)

	for _, inv := range invs {
		pkgInfo := imodels.FromInventory(inv)
		if pkgInfo.Name() == "" || pkgInfo.Ecosystem().IsEmpty() {
			continue
		}
		pkg := osvdev.Package{
			Name:      pkgInfo.Name(),
			Ecosystem: pkgInfo.Ecosystem().String(),
		}

		if _, ok := matcher.vulnCache.Load(pkg); ok {
			plan.cacheHits++
			continue
		}

		occurrenceCounts[pkg]++
		if _, ok := toQuery[pkg]; ok {
			plan.duplicateSuppressed++
			continue
		}

		toQuery[pkg] = struct{}{}
		plan.queries = append(plan.queries, &osvdev.Query{Package: pkg})
	}

	for pkg, count := range occurrenceCounts {
		if count <= 1 {
			continue
		}
		plan.repeatedPackageLines = append(
			plan.repeatedPackageLines,
			fmt.Sprintf(
				"ecosystem=%s package=%s occurrences=%d suppressed_duplicate_entries=%d deduped_query_entry=true",
				pkg.Ecosystem,
				pkg.Name,
				count,
				count-1,
			),
		)
	}
	slices.Sort(plan.repeatedPackageLines)

	return plan
}

func (matcher *CachedOSVMatcher) doQueries(ctx context.Context, invs []*extractor.Package) (cachedQueryPlan, batchQueryMetrics, error) {
	var batchResp *osvdev.BatchedResponse
	deadlineExceeded := false

	plan := matcher.buildQueryPlan(invs)
	queries := plan.queries
	queryMetrics := batchQueryMetrics{}

	if len(queries) == 0 {
		return plan, queryMetrics, nil
	}

	var err error

	// If there is a timeout for the initial query, set an additional context deadline here.
	if matcher.InitialQueryTimeout > 0 {
		batchQueryCtx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(matcher.InitialQueryTimeout))
		batchResp, err = batchQueryPagingWithMetrics(batchQueryCtx, &matcher.Client, queries, &queryMetrics)
		cancelFunc()
	} else {
		batchResp, err = batchQueryPagingWithMetrics(ctx, &matcher.Client, queries, &queryMetrics)
	}

	if err != nil {
		// Deadline being exceeded is likely caused by a long paging time
		// if that's the case, we should return what we already got, and
		// then let the caller know it is not all the results.
		if errors.Is(err, context.DeadlineExceeded) {
			deadlineExceeded = true
		} else {
			return plan, queryMetrics, err
		}
	}

	// No results found - this could be due to a timeout
	if batchResp == nil {
		return plan, queryMetrics, err
	}

	vulnerabilities := make([][]osvschema.Vulnerability, len(batchResp.Results))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.Results {
		queryMetrics.vulnDetailRequests += len(resp.Vulns)
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
		return plan, queryMetrics, err
	}

	if deadlineExceeded {
		return plan, queryMetrics, context.DeadlineExceeded
	}

	for i, vulns := range vulnerabilities {
		matcher.vulnCache.Store(queries[i].Package, vulns)
	}

	return plan, queryMetrics, nil
}

func (matcher *CachedOSVMatcher) matchDirectQueries(ctx context.Context, invs []*extractor.Package) ([]directQueryResult, batchQueryMetrics, error) {
	if len(invs) == 0 {
		return nil, batchQueryMetrics{}, nil
	}

	var batchResp *osvdev.BatchedResponse
	deadlineExceeded := false
	queryMetrics := batchQueryMetrics{}
	queries := invsToQueries(invs)

	var err error
	if matcher.InitialQueryTimeout > 0 {
		batchQueryCtx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(matcher.InitialQueryTimeout))
		batchResp, err = batchQueryPagingWithMetrics(batchQueryCtx, &matcher.Client, queries, &queryMetrics)
		cancelFunc()
	} else {
		batchResp, err = batchQueryPagingWithMetrics(ctx, &matcher.Client, queries, &queryMetrics)
	}

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			deadlineExceeded = true
		} else {
			return nil, queryMetrics, err
		}
	}

	if batchResp == nil {
		return nil, queryMetrics, err
	}

	results := make([]directQueryResult, len(batchResp.Results))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.Results {
		results[batchIdx] = directQueryResult{
			vulnerabilities: make([]*osvschema.Vulnerability, len(resp.Vulns)),
		}
		queryMetrics.vulnDetailRequests += len(resp.Vulns)

		for resultIdx, vuln := range resp.Vulns {
			g.Go(func() error {
				if ctx.Err() != nil {
					return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
				}
				vuln, err := matcher.Client.GetVulnByID(ctx, vuln.ID)
				if err != nil {
					return err
				}
				results[batchIdx].vulnerabilities[resultIdx] = vuln

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return nil, queryMetrics, err
	}

	if deadlineExceeded {
		return results, queryMetrics, context.DeadlineExceeded
	}

	return results, queryMetrics, nil
}

func (matcher *CachedOSVMatcher) logSummary(inventoryCount int, plan cachedQueryPlan, metrics batchQueryMetrics) {
	slog.Info("osv matcher=cached")
	slog.Info("  summary:")
	slog.Info(fmt.Sprintf("  - inventories=%d", inventoryCount))
	slog.Info(fmt.Sprintf("  - deduped_batched_package_query_entries=%d", len(plan.queries)))
	slog.Info(fmt.Sprintf("  - duplicate_package_entries_suppressed=%d", plan.duplicateSuppressed))
	slog.Info(fmt.Sprintf("  - package_cache_hits=%d", plan.cacheHits))
	slog.Info(fmt.Sprintf("  - query_batch_requests=%d", metrics.queryBatchRequests))
	if len(plan.repeatedPackageLines) > 0 {
		slog.Info("  repeated_packages:")
		for _, repeatedPkg := range plan.repeatedPackageLines {
			slog.Info("  - " + repeatedPkg)
		}
	}
	slog.Info(fmt.Sprintf("  - vulnerability_detail_requests=%d", metrics.vulnDetailRequests))
}

func shouldUseCachedPackageQuery(pkgInfo imodels.PackageInfo) bool {
	if pkgInfo.Name() == "" || pkgInfo.Ecosystem().IsEmpty() || pkgInfo.Version() == "" {
		return false
	}

	if pkgInfo.Ecosystem().String() != "Go" {
		return false
	}

	_, err := semantic.Parse(pkgInfo.Version(), pkgInfo.Ecosystem().String())

	return err == nil
}
