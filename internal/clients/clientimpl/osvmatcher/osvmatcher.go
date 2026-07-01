package osvmatcher

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/purl"
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
	var queryIndexes []int
	deadlineExceeded := false

	{
		var err error

		// Convert packages to unique queries while keeping enough information to
		// expand results back to the original package order.
		queries, indexes := pkgsToUniqueQueries(pkgs)
		queryIndexes = indexes
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

	uniqueVulnerabilities := make([][]*osvschema.Vulnerability, len(batchResp.GetResults()))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.GetResults() {
		uniqueVulnerabilities[batchIdx] = make([]*osvschema.Vulnerability, len(resp.GetVulns()))
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
				uniqueVulnerabilities[batchIdx][resultIdx] = vuln

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	vulnerabilities := expandQueryResults(uniqueVulnerabilities, queryIndexes)
	if deadlineExceeded {
		return vulnerabilities, context.DeadlineExceeded
	}

	return vulnerabilities, nil
}

// rhelFamilyEpochEcosystems are the RPM ecosystems whose osv.dev advisory
// records encode the package epoch (verified against api.osv.dev). Only these
// receive an epoch-qualified query version. Some RPM ecosystems (e.g. openEuler)
// store epoch-less records even though their packages carry epochs; sending an
// epoch there would make every epoch-bearing package look newer than its fix and
// be reported as unaffected. Leaving such ecosystems epoch-less is the safe
// default (no regression); entries are added only once epoch-encoding is verified.
var rhelFamilyEpochEcosystems = map[string]bool{
	"Red Hat":     true,
	"AlmaLinux":   true,
	"Rocky Linux": true,
}

// ecosystemEncodesEpoch reports whether the ecosystem's OSV records carry the
// RPM epoch, so a query for it must be epoch-qualified to compare correctly.
func ecosystemEncodesEpoch(ecosystem string) bool {
	distro, _, _ := strings.Cut(ecosystem, ":")
	return rhelFamilyEpochEcosystems[distro]
}

// queryVersion returns the version string to send to osv.dev for a package.
// RPM ecosystems order versions with an epoch, but scalibr stores it separately
// from the version string. For ecosystems whose records encode the epoch, it is
// prepended when non-zero (e.g. "3.2.2-7.el9_6" -> "1:3.2.2-7.el9_6"); otherwise
// osv.dev treats the missing epoch as 0, making the installed package look older
// than every epoch-bearing fix and reporting already-fixed advisories as unfixed.
// Ecosystems that store epoch-less records, and non-RPM ecosystems (which carry
// any epoch inline), are returned unchanged.
func queryVersion(pkg *extractor.Package, ecosystem string) string {
	version := imodels.Version(pkg)
	if m, ok := pkg.Metadata.(*rpmmetadata.Metadata); ok && m.Epoch > 0 && ecosystemEncodesEpoch(ecosystem) {
		return strconv.Itoa(m.Epoch) + ":" + version
	}

	return version
}

func pkgToQuery(pkg *extractor.Package) *api.Query {
	if imodels.Name(pkg) != "" && !imodels.Ecosystem(pkg).IsEmpty() && imodels.Version(pkg) != "" {
		name := imodels.Name(pkg)

		// Tools like Syft create Go PURLs where the module's major suffix is part
		// of the subpath as opposed to the package name:
		//
		// pkg:golang/github.com/go-jose/go-jose@v4.1.3#v4
		//
		// For a correct match we need to add the major suffix back
		if imodels.Ecosystem(pkg).Ecosystem == osvconstants.EcosystemGo && pkg.PURL().Subpath != "" {
			match := goVersionSuffixRegexp.FindStringSubmatch(pkg.PURL().Subpath)
			if match != nil {
				name += "/" + match[1]
			}
		}

		// Special case for Homebrew packages with a source code repo
		if pkg.PURL().Type == purl.TypeBrew && pkg.SourceCode != nil {
			name = strings.ToLower(pkg.SourceCode.Repo)
		}

		return &api.Query{
			Package: &osvschema.Package{
				Name:      name,
				Ecosystem: imodels.Ecosystem(pkg).String(),
			},
			Param: &api.Query_Version{
				Version: queryVersion(pkg, imodels.Ecosystem(pkg).String()),
			},
		}
	}

	if imodels.Commit(pkg) != "" {
		return &api.Query{
			Param: &api.Query_Commit{
				Commit: imodels.Commit(pkg),
			},
		}
	}

	// This should have be filtered out before reaching this point
	cmdlogger.Errorf("invalid query element: %#v", pkg)

	return nil
}

// pkgsToUniqueQueries converts packages to deduplicated OSV queries while
// preserving a mapping back to the original package order.
func pkgsToUniqueQueries(pkgs []*extractor.Package) ([]*api.Query, []int) {
	queries := make([]*api.Query, 0, len(pkgs))
	queryIndexes := make([]int, len(pkgs))
	seen := make(map[string]int, len(pkgs))

	for i, pkg := range pkgs {
		query := pkgToQuery(pkg)
		key := queryKey(query)
		if queryIdx, ok := seen[key]; ok {
			queryIndexes[i] = queryIdx
			continue
		}
		queryIndexes[i] = len(queries)
		seen[key] = len(queries)
		queries = append(queries, query)
	}

	return queries, queryIndexes
}

func queryKey(query *api.Query) string {
	if query == nil {
		return "nil"
	}
	if query.GetCommit() != "" {
		return "commit\x00" + query.GetCommit()
	}

	pkg := query.GetPackage()

	return "version\x00" + pkg.GetEcosystem() + "\x00" + pkg.GetName() + "\x00" + query.GetVersion()
}

func expandQueryResults(uniqueResults [][]*osvschema.Vulnerability, queryIndexes []int) [][]*osvschema.Vulnerability {
	results := make([][]*osvschema.Vulnerability, len(queryIndexes))
	for i, queryIdx := range queryIndexes {
		if queryIdx < len(uniqueResults) {
			results[i] = uniqueResults[queryIdx]
		}
	}

	return results
}
