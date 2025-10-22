// Package licensematcher implements a client for matching licenses using the deps.dev API.
package licensematcher

import (
	"context"

	depsdevpb "deps.dev/api/v3"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scanner/v2/internal/depsdev"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/pkg/models"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxConcurrentRequests = 1000
)

// DepsDevLicenseMatcher implements the LicenseMatcher interface with a deps.dev client.
// It sends out requests for every package version and does not perform caching.
type DepsDevLicenseMatcher struct {
	Client *datasource.CachedInsightsClient
}

func (matcher *DepsDevLicenseMatcher) MatchLicenses(ctx context.Context, packages []imodels.PackageScanResult) error {
	queries := make([]*depsdevpb.GetVersionRequest, len(packages))

	for i, psr := range packages {
		pkg := psr.PackageInfo
		system, ok := depsdev.System[psr.PackageInfo.Ecosystem().Ecosystem]
		if !ok || pkg.Name() == "" || pkg.Version() == "" {
			continue
		}
		queries[i] = versionQuery(system, pkg.Name(), pkg.Version())
	}

	licenses, err := matcher.makeVersionRequest(ctx, queries)
	if err != nil {
		return err
	}

	for i, license := range licenses {
		packages[i].Licenses = license
	}

	return nil
}

// makeVersionRequest calls the deps.dev GetVersion gRPC API endpoint for each
// query. It makes these requests concurrently, sharing the single HTTP/2
// connection. The order in which the requests are specified should correspond
// to the order of licenses returned by this function.
func (matcher *DepsDevLicenseMatcher) makeVersionRequest(ctx context.Context, queries []*depsdevpb.GetVersionRequest) ([][]models.License, error) {
	licenses := make([][]models.License, len(queries))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for i := range queries {
		if queries[i] == nil {
			// This may be a private package.
			licenses[i] = []models.License{models.License("UNKNOWN")}
			continue
		}
		g.Go(func() error {
			resp, err := matcher.Client.GetVersion(ctx, queries[i])
			if err != nil {
				if status.Code(err) == codes.NotFound {
					licenses[i] = append(licenses[i], "UNKNOWN")
					return nil
				}

				return err
			}
			ls := make([]models.License, len(resp.GetLicenses()))
			for j, license := range resp.GetLicenses() {
				ls[j] = models.License(license)
			}
			if len(ls) == 0 {
				// The deps.dev API will return an
				// empty slice if the license is
				// unknown.
				ls = []models.License{models.License("UNKNOWN")}
			}
			licenses[i] = ls

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return licenses, nil
}

func versionQuery(system depsdevpb.System, name string, version string) *depsdevpb.GetVersionRequest {
	if system == depsdevpb.System_GO && name != "stdlib" {
		version = "v" + version
	}

	return &depsdevpb.GetVersionRequest{
		VersionKey: &depsdevpb.VersionKey{
			System:  system,
			Name:    name,
			Version: version,
		},
	}
}
