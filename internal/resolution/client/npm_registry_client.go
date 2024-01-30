package client

import (
	"context"
	"encoding/gob"
	"fmt"
	"os"
	"slices"
	"strings"

	pb "deps.dev/api/v3alpha"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/semver"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/pkg/depsdev"
)

const npmRegistryCacheExt = ".resolve.npm"

type NpmRegistryClient struct {
	api      *datasource.NpmRegistryAPIClient
	fallback *DepsDevClient // fallback client for dealing with bundleDependencies
}

func NewNpmRegistryClient(workdir string) (*NpmRegistryClient, error) {
	api, err := datasource.NewNpmRegistryAPIClient(workdir)
	if err != nil {
		return nil, err
	}

	ddClient, err := NewDepsDevClient(depsdev.DepsdevAPI)
	if err != nil {
		return nil, err
	}

	return &NpmRegistryClient{
		api:      api,
		fallback: ddClient,
	}, nil
}

func (c *NpmRegistryClient) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	if strings.Contains(vk.Name, ">") { // bundled dependencies, fallback to deps.dev client
		return c.fallback.Version(ctx, vk)
	}

	return resolve.Version{VersionKey: vk}, nil
}

func (c *NpmRegistryClient) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	if strings.Contains(pk.Name, ">") { // bundled dependencies, fallback to deps.dev client
		return c.fallback.Versions(ctx, pk)
	}

	vers, err := c.api.Versions(ctx, pk.Name)
	if err != nil {
		return nil, err
	}

	vks := make([]resolve.Version, len(vers.Versions))
	for i, v := range vers.Versions {
		vks[i] = resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				Version:     v,
				VersionType: resolve.Concrete,
			}}
	}

	slices.SortFunc(vks, func(a, b resolve.Version) int { return semver.NPM.Compare(a.Version, b.Version) })

	return vks, nil
}

func (c *NpmRegistryClient) Requirements(ctx context.Context, vk resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	if vk.System != resolve.NPM {
		return nil, fmt.Errorf("unsupported system: %v", vk.System)
	}

	if strings.Contains(vk.Name, ">") { // bundled dependencies, fallback to deps.dev client
		return c.fallback.Requirements(ctx, vk)
	}
	dependencies, err := c.api.Dependencies(ctx, vk.Name, vk.Version)
	if err != nil {
		return nil, err
	}

	depCount := len(dependencies.Dependencies) + len(dependencies.DevDependencies) +
		len(dependencies.OptionalDependencies) + len(dependencies.PeerDependencies) +
		2*len(dependencies.BundleDependencies)
	deps := make([]resolve.RequirementVersion, 0, depCount)
	addDeps := func(ds map[string]string, t dep.Type) {
		for name, req := range ds {
			typ := t.Clone()
			if r, ok := strings.CutPrefix(req, "npm:"); ok {
				// This dependency is aliased, add it as a
				// dependency on the actual name, with the
				// KnownAs attribute set to the alias.
				typ.AddAttr(dep.KnownAs, name)
				name = r
				req = ""
				if i := strings.LastIndex(r, "@"); i > 0 {
					name = r[:i]
					req = r[i+1:]
				}
			}
			deps = append(deps, resolve.RequirementVersion{
				Type: typ,
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.NPM,
						Name:   name,
					},
					VersionType: resolve.Requirement,
					Version:     req,
				},
			})
		}
	}
	addDeps(dependencies.Dependencies, dep.NewType())
	addDeps(dependencies.DevDependencies, dep.NewType(dep.Dev))
	addDeps(dependencies.OptionalDependencies, dep.NewType(dep.Opt))

	peerType := dep.NewType()
	peerType.AddAttr(dep.Scope, "peer")
	addDeps(dependencies.PeerDependencies, peerType)

	// The resolver expects bundleDependencies to be present as regular
	// dependencies with a "*" version specifier, even if they were already
	// in the regular dependencies.
	bundleType := dep.NewType()
	bundleType.AddAttr(dep.Scope, "bundle")
	for _, name := range dependencies.BundleDependencies {
		deps = append(deps, resolve.RequirementVersion{
			Type: bundleType,
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.NPM,
					Name:   name,
				},
				VersionType: resolve.Requirement,
				Version:     "*",
			},
		})
	}

	// Correctly resolving the bundled dependencies would require downloading the package
	// call the fallback deps.dev client to get the bundled dependencies with mangled names
	if len(dependencies.BundleDependencies) > 0 {
		fallbackReqs, err := c.fallback.Requirements(ctx, vk)
		if err != nil {
			// TODO: make some placeholder if the package doesn't exist in the deps.dev data
			return nil, err
		}
		for _, req := range fallbackReqs {
			if strings.Contains(req.Name, ">") {
				deps = append(deps, req)
			}
		}
	}

	resolve.SortDependencies(deps)

	return deps, nil
}

func (c *NpmRegistryClient) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	if strings.Contains(vk.Name, ">") { // bundled dependencies, fallback to deps.dev client
		return c.fallback.MatchingVersions(ctx, vk)
	}

	versions, err := c.api.Versions(ctx, vk.Name)
	if err != nil {
		return nil, err
	}

	if concVer, ok := versions.Tags[vk.Version]; ok {
		// matched a tag, return just the concrete version of the tag
		return []resolve.Version{{
			VersionKey: resolve.VersionKey{
				PackageKey:  vk.PackageKey,
				Version:     concVer,
				VersionType: resolve.Concrete,
			},
		},
		}, nil
	}

	resVersions := make([]resolve.Version, len(versions.Versions))
	for i, v := range versions.Versions {
		resVersions[i] = resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  vk.PackageKey,
				Version:     v,
				VersionType: resolve.Concrete,
			},
		}
	}

	return resolve.MatchRequirement(vk, resVersions), nil
}

func (c *NpmRegistryClient) PreFetch(ctx context.Context, imports []resolve.RequirementVersion, manifestPath string) {
	// It doesn't matter if loading the cache fails
	_ = c.LoadCache(manifestPath)

	// Use the deps.dev client to fetch complete dependency graphs of our direct imports
	for _, im := range imports {
		// Get the preferred version of the import requirement
		vks, err := c.MatchingVersions(ctx, im.VersionKey)
		if err != nil || len(vks) == 0 {
			continue
		}

		vk := vks[len(vks)-1]

		// Make a request for the precomputed dependency tree
		// TODO: avoid relying on DepsDevClient internals
		resp, err := c.fallback.c.GetDependencies(ctx, &pb.GetDependenciesRequest{
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
			vk := resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.System(pbvk.GetSystem()),
					Name:   pbvk.GetName(),
				},
				Version:     pbvk.GetVersion(),
				VersionType: resolve.Concrete,
			}
			go c.Requirements(ctx, vk) //nolint:errcheck
		}
	}
	// don't bother waiting for goroutines to finish.
}

func (c *NpmRegistryClient) WriteCache(path string) error {
	f, err := os.Create(path + npmRegistryCacheExt)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewEncoder(f).Encode(c.api)
	// Don't bother storing the fallback client's cache
}

func (c *NpmRegistryClient) LoadCache(path string) error {
	f, err := os.Open(path + npmRegistryCacheExt)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewDecoder(f).Decode(&c.api)
}
