// Package depsdev contains constants and mappings for the deps.dev API.
package depsdev

import (
	"crypto/x509"
	"fmt"

	v3 "deps.dev/api/v3"
	"deps.dev/api/v3alpha"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DepsdevAPI is the URL to the deps.dev API. It is documented at
// docs.deps.dev/api.
const DepsdevAPI = "api.deps.dev:443"

// System maps from a lockfile system to the depsdev API system.
var System = map[osvconstants.Ecosystem]v3.System{
	osvconstants.EcosystemNPM:      v3.System_NPM,
	osvconstants.EcosystemNuGet:    v3.System_NUGET,
	osvconstants.EcosystemCratesIO: v3.System_CARGO,
	osvconstants.EcosystemGo:       v3.System_GO,
	osvconstants.EcosystemMaven:    v3.System_MAVEN,
	osvconstants.EcosystemPyPI:     v3.System_PYPI,
	osvconstants.EcosystemRubyGems: v3.System_RUBYGEMS,
}

// NewInsightsAlphaClient creates a deps.dev v3alpha InsightsClient with a custom address and userAgent.
func NewInsightsAlphaClient(addr string, userAgent string) (v3alpha.InsightsClient, error) {
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

	return v3alpha.NewInsightsClient(conn), nil
}
