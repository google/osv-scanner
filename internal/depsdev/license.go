package depsdev

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

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
var System = map[osvschema.Ecosystem]depsdevpb.System{
	osvschema.EcosystemNPM:      depsdevpb.System_NPM,
	osvschema.EcosystemNuGet:    depsdevpb.System_NUGET,
	osvschema.EcosystemCratesIO: depsdevpb.System_CARGO,
	osvschema.EcosystemGo:       depsdevpb.System_GO,
	osvschema.EcosystemMaven:    depsdevpb.System_MAVEN,
	osvschema.EcosystemPyPI:     depsdevpb.System_PYPI,
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
