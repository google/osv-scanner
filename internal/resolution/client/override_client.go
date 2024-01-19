package client

import (
	"context"
	"slices"

	"deps.dev/util/resolve"
)

// OvverideClient wraps a resolve.Client, allowing for custom packages & versions to be added
type OverrideClient struct {
	c resolve.Client

	// Can't quite reuse resolve.LocalClient because it automatically creates dependencies
	pkgVers map[resolve.PackageKey][]resolve.Version            // versions of a package
	verDeps map[resolve.VersionKey][]resolve.RequirementVersion // dependencies of a version
}

func NewOverrideClient(c resolve.Client) *OverrideClient {
	return &OverrideClient{
		c:       c,
		pkgVers: make(map[resolve.PackageKey][]resolve.Version),
		verDeps: make(map[resolve.VersionKey][]resolve.RequirementVersion),
	}
}

func (c *OverrideClient) AddVersion(v resolve.Version, deps []resolve.RequirementVersion) {
	// TODO: Inserting multiple co-dependent requirements may not work, depending on order
	versions := c.pkgVers[v.PackageKey]
	sem := v.Semver()
	// Only add it to the versions if not already there (and keep versions sorted)
	idx, ok := slices.BinarySearchFunc(versions, v, func(a, b resolve.Version) int {
		return sem.Compare(a.Version, b.Version)
	})
	if !ok {
		versions = slices.Insert(versions, idx, v)
	}
	c.pkgVers[v.PackageKey] = versions
	c.verDeps[v.VersionKey] = slices.Clone(deps) // overwrites dependencies if called multiple times with same version
}

func (c *OverrideClient) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	for _, v := range c.pkgVers[vk.PackageKey] {
		if v.VersionKey == vk {
			return v, nil
		}
	}

	return c.c.Version(ctx, vk)
}

func (c *OverrideClient) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	if vers, ok := c.pkgVers[pk]; ok {
		return vers, nil
	}

	return c.c.Versions(ctx, pk)
}

func (c *OverrideClient) Requirements(ctx context.Context, vk resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	if deps, ok := c.verDeps[vk]; ok {
		return deps, nil
	}

	return c.c.Requirements(ctx, vk)
}

func (c *OverrideClient) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	if vs, ok := c.pkgVers[vk.PackageKey]; ok {
		return resolve.MatchRequirement(vk, vs), nil
	}

	return c.c.MatchingVersions(ctx, vk)
}
