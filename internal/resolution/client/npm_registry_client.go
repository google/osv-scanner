package client

import (
	"context"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"os"
	"slices"
	"strings"

	pb "deps.dev/api/v3"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/semver"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/pkg/osv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const npmRegistryCacheExt = ".resolve.npm"

type NpmRegistryClient struct {
	api *datasource.NpmRegistryAPIClient

	// Fallback client for dealing with bundleDependencies.
	ic       pb.InsightsClient
	fallback *resolve.APIClient
}

func NewNpmRegistryClient(workdir string) (*NpmRegistryClient, error) {
	api, err := datasource.NewNpmRegistryAPIClient(workdir)
	if err != nil {
		return nil, err
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("getting system cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	if osv.RequestUserAgent != "" {
		dialOpts = append(dialOpts, grpc.WithUserAgent(osv.RequestUserAgent))
	}

	conn, err := grpc.NewClient(depsdev.DepsdevAPI, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dialling %q: %w", depsdev.DepsdevAPI, err)
	}
	ic := pb.NewInsightsClient(conn)

	return &NpmRegistryClient{
		api:      api,
		ic:       ic,
		fallback: resolve.NewAPIClient(ic),
	}, nil
}

func (c *NpmRegistryClient) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	if isNpmBundle(vk.PackageKey) { // bundled dependencies, fallback to deps.dev client
		return c.fallback.Version(ctx, vk)
	}

	return resolve.Version{VersionKey: vk}, nil
}

func (c *NpmRegistryClient) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	if isNpmBundle(pk) { // bundled dependencies, fallback to deps.dev client
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

	if isNpmBundle(vk.PackageKey) { // bundled dependencies, fallback to deps.dev client
		return c.fallback.Requirements(ctx, vk)
	}
	dependencies, err := c.api.Dependencies(ctx, vk.Name, vk.Version)
	if err != nil {
		return nil, err
	}

	// Preallocate the dependency slice, which will hold all the dependencies of each type.
	// The npm resolver expects bundled dependencies included twice in different forms:
	// {foo@*|Scope="bundle"} and {mangled-name-of>0.1.2>foo@1.2.3}, hence the 2*len(bundled)
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

	// Correctly resolving the bundled dependencies would require downloading the package.
	// Instead, call the fallback deps.dev client to get the bundled dependencies with mangled names.
	if len(dependencies.BundleDependencies) > 0 {
		fallbackReqs, err := c.fallback.Requirements(ctx, vk)
		if err != nil {
			// TODO: make some placeholder if the package doesn't exist on deps.dev
			return nil, err
		}
		for _, req := range fallbackReqs {
			if isNpmBundle(req.PackageKey) {
				deps = append(deps, req)
			}
		}
	}

	resolve.SortDependencies(deps)

	return deps, nil
}

func (c *NpmRegistryClient) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	if isNpmBundle(vk.PackageKey) { // bundled dependencies, fallback to deps.dev client
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
		}}, nil
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

func isNpmBundle(pk resolve.PackageKey) bool {
	// Bundles are represented in resolution with a 'mangled' name containing its origin e.g. "root-pkg>1.0.0>bundled-package"
	// '>' is not a valid character for a npm package, so it'll only be found here.
	return strings.Contains(pk.Name, ">")
}

func (c *NpmRegistryClient) AddRegistries(_ []Registry) error { return nil }

func (c *NpmRegistryClient) WriteCache(path string) error {
	f, err := os.Create(path + npmRegistryCacheExt)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewEncoder(f).Encode(c.api)
}

func (c *NpmRegistryClient) LoadCache(path string) error {
	f, err := os.Open(path + npmRegistryCacheExt)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewDecoder(f).Decode(&c.api)
}
