// Package client defines the clients for resolving dependencies for various ecosystems.
package client

import (
	"context"
	"crypto/x509"

	pb "deps.dev/api/v3"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/semver"
	"github.com/google/osv-scanner/v2/internal/clients/clientinterfaces"
	"github.com/google/osv-scanner/v2/internal/depsdev"
	"github.com/google/osv-scanner/v2/internal/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ResolutionClient struct {
	DependencyClient
	clientinterfaces.VulnerabilityMatcher
}

type DependencyClient interface {
	resolve.Client
	// WriteCache writes a manifest-specific resolution cache.
	WriteCache(filepath string) error
	// LoadCache loads a manifest-specific resolution cache.
	LoadCache(filepath string) error
	// AddRegistries adds the specified registries to fetch data.
	AddRegistries(registries []Registry) error
}

type Registry any

// PreFetch loads cache, then makes and caches likely queries needed for resolving a package with a list of requirements
func PreFetch(ctx context.Context, c DependencyClient, requirements []resolve.RequirementVersion, manifestPath string) {
	// It doesn't matter if loading the cache fails
	_ = c.LoadCache(manifestPath)

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithUserAgent("osv-scanner/" + version.OSVVersion),
	}

	conn, err := grpc.NewClient(depsdev.DepsdevAPI, dialOpts...)
	if err != nil {
		return
	}
	insights := pb.NewInsightsClient(conn)

	// Use the deps.dev client to fetch complete dependency graphs of our direct imports
	for _, im := range requirements {
		// There are potentially a huge number of management/import dependencies.
		if im.Type.HasAttr(dep.MavenDependencyOrigin) {
			continue
		}

		var vk resolve.Version
		var constraint *semver.Constraint
		// Maven registry client may be slow calling MatchingVersions which makes requests to `maven-metadata.xml`.
		// We can avoid this by only calling MatchingVersions for non-soft requirements.
		if im.System == resolve.Maven {
			if constraint, err = semver.Maven.ParseConstraint(im.Version); err != nil {
				continue
			}
		}
		if constraint != nil && constraint.IsSimple() {
			// If the requirement is a simple version, use it as the VersionKey,
			// so we do not need to call MatchingVersions to get available versions.
			vk = resolve.Version{
				VersionKey: im.VersionKey,
			}
		} else {
			// Get the preferred version of the import requirement
			vks, err := c.MatchingVersions(ctx, im.VersionKey)
			if err != nil || len(vks) == 0 {
				continue
			}
			vk = vks[len(vks)-1]
		}

		// Make a request for the precomputed dependency tree
		resp, err := insights.GetDependencies(ctx, &pb.GetDependenciesRequest{
			VersionKey: &pb.VersionKey{
				System:  pb.System(vk.System),
				Name:    vk.Name,
				Version: vk.Version,
			},
		})
		if err != nil {
			continue
		}

		// Send off queries to cache the packages in the dependency tree
		nodes := resp.GetNodes()
		for _, node := range nodes {
			pbvk := node.GetVersionKey()
			vk := resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.System(pbvk.GetSystem()),
					Name:   pbvk.GetName(),
				},
				Version:     pbvk.GetVersion(),
				VersionType: resolve.Concrete,
			}

			// TODO: We might want to limit the number of goroutines this creates.
			go c.Requirements(ctx, vk) //nolint:errcheck
			go c.Version(ctx, vk)      //nolint:errcheck
			if vk.System != resolve.Maven {
				// Avoid making requests to `maven-metadata.xml`
				go c.Versions(ctx, vk.PackageKey) //nolint:errcheck
			}
		}
	}
	// don't bother waiting for goroutines to finish.
}
