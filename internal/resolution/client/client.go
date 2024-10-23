package client

import (
	"context"
	"crypto/x509"

	pb "deps.dev/api/v3"
	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ResolutionClient struct {
	DependencyClient
	VulnerabilityClient
}

type VulnerabilityClient interface {
	// FindVulns finds the vulnerabilities affecting each of Nodes in the graph.
	// The returned Vulnerabilities[i] corresponds to the vulnerabilities in g.Nodes[i].
	FindVulns(g *resolve.Graph) ([]models.Vulnerabilities, error)
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

type Registry struct {
	URL string
}

// PreFetch loads cache, then makes and caches likely queries needed for resolving a package with a list of requirements
func PreFetch(ctx context.Context, c DependencyClient, requirements []resolve.RequirementVersion, manifestPath string) {
	// It doesn't matter if loading the cache fails
	_ = c.LoadCache(manifestPath)

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	if osv.RequestUserAgent != "" {
		dialOpts = append(dialOpts, grpc.WithUserAgent(osv.RequestUserAgent))
	}

	conn, err := grpc.NewClient(depsdev.DepsdevAPI, dialOpts...)
	if err != nil {
		return
	}
	insights := pb.NewInsightsClient(conn)

	// Use the deps.dev client to fetch complete dependency graphs of our direct imports
	for _, im := range requirements {
		// Get the preferred version of the import requirement
		vks, err := c.MatchingVersions(ctx, im.VersionKey)
		if err != nil || len(vks) == 0 {
			continue
		}

		vk := vks[len(vks)-1]

		// We prefer the exact version for soft requirements.
		for _, v := range vks {
			if im.Version == v.Version {
				vk = v
				break
			}
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
			go c.Requirements(ctx, vk)        //nolint:errcheck
			go c.Version(ctx, vk)             //nolint:errcheck
			go c.Versions(ctx, vk.PackageKey) //nolint:errcheck
		}

		for _, edge := range resp.GetEdges() {
			req := edge.GetRequirement()
			pbvk := nodes[edge.GetToNode()].GetVersionKey()
			vk := resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.System(pbvk.GetSystem()),
					Name:   pbvk.GetName(),
				},
				Version:     req,
				VersionType: resolve.Requirement,
			}
			go c.MatchingVersions(ctx, vk) //nolint:errcheck
		}
	}

	// don't bother waiting for goroutines to finish.
}
