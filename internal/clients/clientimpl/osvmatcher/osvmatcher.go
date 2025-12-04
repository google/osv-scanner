package osvmatcher

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
	"osv.dev/bindings/go/osvdevexperimental"
)

const (
	maxConcurrentRequests = 1000
)

// goVersionSuffixRegexp matches a Golang major suffix in a PURL's subpath.
//
// Matches:
//   - v4 - v4
//   - /v5/sdk/internal - v5
//
// Does not match:
//   - sdk/internal
//   - /sdk/resourcemanager/iothub/armiothub
var goVersionSuffixRegexp = cachedregexp.MustCompile(`^/?(v\d+)`)

// OSVMatcher implements the VulnerabilityMatcher interface with an osv.dev client.
// It sends out requests for every package version and does not perform caching.
type OSVMatcher struct {
	Client osvdev.OSVClient
	// InitialQueryTimeout allows you to set a timeout specifically for the initial paging query
	// If timeout runs out, whatever pages that has been successfully queried within the timeout will
	// still return fully hydrated.
	InitialQueryTimeout time.Duration
}

func New(initialQueryTimeout time.Duration, userAgent string, httpClient *http.Client) *OSVMatcher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	config := osvdev.DefaultConfig()
	config.UserAgent = userAgent

	return &OSVMatcher{
		Client: osvdev.OSVClient{
			HTTPClient:  httpClient,
			Config:      config,
			BaseHostURL: osvdev.DefaultBaseURL,
		},
		InitialQueryTimeout: initialQueryTimeout,
	}
}

// MatchVulnerabilities matches vulnerabilities for a list of packages.
func (matcher *OSVMatcher) MatchVulnerabilities(ctx context.Context, pkgs []*extractor.Package) ([][]*osvschema.Vulnerability, error) {
	var batchResp *api.BatchVulnerabilityList
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

	vulnerabilities := make([][]*osvschema.Vulnerability, len(batchResp.GetResults()))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.GetResults() {
		vulnerabilities[batchIdx] = make([]*osvschema.Vulnerability, len(resp.GetVulns()))
		for resultIdx, vuln := range resp.GetVulns() {
			g.Go(func() error {
				// exit early if another hydration request has already failed
				// results are thrown away later, so avoid needless work
				if ctx.Err() != nil {
					return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
				}
				vuln, err := matcher.Client.GetVulnByID(ctx, vuln.GetId())
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

func pkgToQuery(pkg imodels.PackageInfo) *api.Query {
	if pkg.Name() != "" && !pkg.Ecosystem().IsEmpty() && pkg.Version() != "" {
		name := pkg.Name()

		// Tools like Syft create Go PURLs where the module's major suffix is part
		// of the subpath as opposed to the package name:
		//
		// pkg:golang/github.com/go-jose/go-jose@v4.1.3#v4
		//
		// For a correct match we need to add the major suffix back
		if pkg.Ecosystem().Ecosystem == osvconstants.EcosystemGo && pkg.PURL().Subpath != "" {
			match := goVersionSuffixRegexp.FindStringSubmatch(pkg.PURL().Subpath)
			if match != nil {
				name += "/" + match[1]
			}
		}

		return &api.Query{
			Package: &osvschema.Package{
				Name:      name,
				Ecosystem: pkg.Ecosystem().String(),
			},
			Param: &api.Query_Version{
				Version: pkg.Version(),
			},
		}
	}

	if pkg.Commit() != "" {
		return &api.Query{
			Param: &api.Query_Commit{
				Commit: pkg.Commit(),
			},
		}
	}

	// This should have be filtered out before reaching this point
	cmdlogger.Errorf("invalid query element: %#v", pkg)

	return nil
}

// invsToQueries converts inventories to queries via the osv-scanner internal imodels
// to perform the necessary transformations
func invsToQueries(invs []*extractor.Package) []*api.Query {
	queries := make([]*api.Query, len(invs))

	for i, inv := range invs {
		pkg := imodels.FromInventory(inv)
		queries[i] = pkgToQuery(pkg)
	}

	return queries
}
