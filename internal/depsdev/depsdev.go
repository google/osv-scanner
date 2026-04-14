// Package depsdev contains constants and mappings for the deps.dev API.
package depsdev

import (
	"crypto/x509"
	"fmt"

	pb "deps.dev/api/v3"
	alphapb "deps.dev/api/v3alpha"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DepsdevAPI is the URL to the deps.dev API. It is documented at
// docs.deps.dev/api.
const DepsdevAPI = "api.deps.dev:443"

// System maps from a lockfile system to the depsdev API system.
var System = map[osvconstants.Ecosystem]pb.System{
	osvconstants.EcosystemNPM:      pb.System_NPM,
	osvconstants.EcosystemNuGet:    pb.System_NUGET,
	osvconstants.EcosystemCratesIO: pb.System_CARGO,
	osvconstants.EcosystemGo:       pb.System_GO,
	osvconstants.EcosystemMaven:    pb.System_MAVEN,
	osvconstants.EcosystemPyPI:     pb.System_PYPI,
	osvconstants.EcosystemRubyGems: pb.System_RUBYGEMS,
}

// NewInsightsAlphaClient creates a deps.dev v3alpha InsightsClient with a custom address and userAgent.
func NewInsightsAlphaClient(addr string, userAgent string) (alphapb.InsightsClient, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("getting system cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	if userAgent != "" {
		dialOpts = append(dialOpts, grpc.WithUserAgent(userAgent))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dialling %q: %w", addr, err)
	}

	return alphapb.NewInsightsClient(conn), nil
}
