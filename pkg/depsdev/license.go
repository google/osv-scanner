package depsdev

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"

	depsdevpb "deps.dev/api/v3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// DepsdevAPI is the URL to the deps.dev API. It is documented at
// docs.deps.dev/api.
const DepsdevAPI = "api.deps.dev:443"

// System maps from a lockfile system to the depsdev API system.
var System = map[lockfile.Ecosystem]depsdevpb.System{
	lockfile.NpmEcosystem:   depsdevpb.System_NPM,
	lockfile.NuGetEcosystem: depsdevpb.System_NUGET,
	lockfile.CargoEcosystem: depsdevpb.System_CARGO,
	lockfile.GoEcosystem:    depsdevpb.System_GO,
	lockfile.MavenEcosystem: depsdevpb.System_MAVEN,
	lockfile.PipEcosystem:   depsdevpb.System_PYPI,
}

// VersionQuery constructs a GetVersion request from the arguments.
func VersionQuery(system depsdevpb.System, name string, version string) *depsdevpb.GetVersionRequest {
	if system == depsdevpb.System_GO {
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

// MakeVersionRequests wraps MakeVersionRequestsWithContext using context.Background.
func MakeVersionRequests(queries []*depsdevpb.GetVersionRequest) ([][]models.License, error) {
	return MakeVersionRequestsWithContext(context.Background(), queries)
}

// MakeVersionRequestsWithContext calls the deps.dev GetVersion gRPC API endpoint for each
// query. It makes these requests concurrently, sharing the single HTTP/2
// connection. The order in which the requests are specified should correspond
// to the order of licenses returned by this function.
func MakeVersionRequestsWithContext(ctx context.Context, queries []*depsdevpb.GetVersionRequest) ([][]models.License, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("getting system cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	if osv.RequestUserAgent != "" {
		dialOpts = append(dialOpts, grpc.WithUserAgent(osv.RequestUserAgent))
	}

	conn, err := grpc.NewClient(DepsdevAPI, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dialing deps.dev gRPC API: %w", err)
	}
	client := depsdevpb.NewInsightsClient(conn)

	licenses := make([][]models.License, len(queries))
	g, ctx := errgroup.WithContext(ctx)
	for i := range queries {
		if queries[i] == nil {
			// This may be a private package.
			licenses[i] = []models.License{models.License("UNKNOWN")}
			continue
		}
		i := i
		g.Go(func() error {
			resp, err := client.GetVersion(ctx, queries[i])
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
