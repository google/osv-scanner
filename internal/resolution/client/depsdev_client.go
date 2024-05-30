package client

import (
	"context"
	"encoding/gob"
	"os"

	pb "deps.dev/api/v3"
	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/resolution/datasource"
)

const depsDevCacheExt = ".resolve.deps"

// DepsDevClient is a ResolutionClient wrapping the official resolve.APIClient
type DepsDevClient struct {
	resolve.APIClient
	c *datasource.DepsDevAPIClient
}

func NewDepsDevClient(addr string) (*DepsDevClient, error) {
	c, err := datasource.NewDepsDevAPIClient(addr)
	if err != nil {
		return nil, err
	}

	return &DepsDevClient{APIClient: *resolve.NewAPIClient(c), c: c}, nil
}

func (d *DepsDevClient) PreFetch(ctx context.Context, requirements []resolve.RequirementVersion, manifestPath string) {
	// It doesn't matter if loading the cache fails
	_ = d.LoadCache(manifestPath)

	// Use the deps.dev client to fetch complete dependency graphs of the direct requirements
	for _, im := range requirements {
		// Get the preferred version of the import requirement
		vks, err := d.MatchingVersions(ctx, im.VersionKey)
		if err != nil || len(vks) == 0 {
			continue
		}

		vk := vks[len(vks)-1]

		// Make a request for the precomputed dependency tree
		resp, err := d.c.GetDependencies(ctx, &pb.GetDependenciesRequest{
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
		for _, node := range resp.GetNodes() {
			pbvk := node.GetVersionKey()

			pk := resolve.PackageKey{
				System: resolve.System(pbvk.GetSystem()),
				Name:   pbvk.GetName(),
			}
			go d.Versions(ctx, pk) //nolint:errcheck

			vk := resolve.VersionKey{
				PackageKey:  pk,
				Version:     pbvk.GetVersion(),
				VersionType: resolve.Concrete,
			}
			go d.Requirements(ctx, vk) //nolint:errcheck
			go d.Version(ctx, vk)      //nolint:errcheck
		}
	}
	// Don't bother waiting for these goroutines to finish.
}

func (d *DepsDevClient) WriteCache(path string) error {
	f, err := os.Create(path + depsDevCacheExt)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewEncoder(f).Encode(d.c)
}

func (d *DepsDevClient) LoadCache(path string) error {
	f, err := os.Open(path + depsDevCacheExt)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewDecoder(f).Decode(&d.c)
}
