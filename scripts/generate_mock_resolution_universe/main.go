package main

// Generate a MockResolutionClient universe file based on real packages encountered during in-place and/or relock updates.
// Used for generating test fixtures.
// Usage: go run ./generate_mock_resolution_universe [list of manifests / lockfiles] > output.yaml
// Will automatically attempt in-place updates and relock/relax updates on all supplied lockfiles/manifests,
// And write all encountered package versions to the output, along with all vulnerabilities for each package.
// Lockfiles/manifests are assumed to be all from the same ecosystem.

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	pb "deps.dev/api/v3"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/depsdev"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/remediation/upgrade"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/clienttest"
	"github.com/google/osv-scanner/internal/resolution/lockfile"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/resolution/util"
	lf "github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

var remediationOpts = remediation.Options{
	ResolveOpts: resolution.ResolveOpts{
		MavenManagement: true,
	},
	DevDeps:       true,
	MaxDepth:      -1,
	UpgradeConfig: upgrade.NewConfig(),
}

func doRelockRelax(ddCl *client.DepsDevClient, rw manifest.ReadWriter, filename string) error {
	cl := client.ResolutionClient{
		VulnerabilityClient: client.NewOSVClient(),
		DependencyClient:    ddCl,
	}

	f, err := lf.OpenLocalDepFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	manif, err := rw.Read(f)
	if err != nil {
		return err
	}

	client.PreFetch(context.Background(), cl, manif.Requirements, manif.FilePath)
	res, err := resolution.Resolve(context.Background(), cl, manif, remediationOpts.ResolveOpts)
	if err != nil {
		return err
	}
	_, err = remediation.ComputeRelaxPatches(context.Background(), cl, res, remediationOpts)

	return err
}

func doOverride(ddCl *client.DepsDevClient, rw manifest.ReadWriter, filename string) error {
	cl := client.ResolutionClient{
		VulnerabilityClient: client.NewOSVClient(),
		DependencyClient:    ddCl,
	}

	f, err := lf.OpenLocalDepFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	manif, err := rw.Read(f)
	if err != nil {
		return err
	}

	client.PreFetch(context.Background(), cl, manif.Requirements, manif.FilePath)
	res, err := resolution.Resolve(context.Background(), cl, manif, remediationOpts.ResolveOpts)
	if err != nil {
		return err
	}
	_, err = remediation.ComputeOverridePatches(context.Background(), cl, res, remediationOpts)

	return err
}

func doInPlace(ddCl *client.DepsDevClient, rw lockfile.ReadWriter, filename string) error {
	cl := client.ResolutionClient{
		VulnerabilityClient: client.NewOSVClient(),
		DependencyClient:    ddCl,
	}

	f, err := lf.OpenLocalDepFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	g, err := rw.Read(f)
	if err != nil {
		return err
	}

	// In-place updating doesn't actually check the client for the packages in the lockfile.
	// For good measure, we do it here to load them into the cache.
	group := &errgroup.Group{}
	for _, n := range g.Nodes {
		vk := n.Version
		group.Go(func() error {
			_, err := ddCl.Requirements(context.Background(), vk)
			return err
		})
	}
	_ = group.Wait()

	_, err = remediation.ComputeInPlacePatches(context.Background(), cl, g, remediationOpts)

	return err
}

func getCachedVersions(cl *client.DepsDevClient) (map[resolve.PackageKey][]string, error) {
	// Abuse the cache writing to get the list of encountered package versions.
	cachePath := filepath.Join(os.TempDir(), "gr-cache")
	if err := cl.WriteCache(cachePath); err != nil {
		return nil, err
	}
	cacheFile := cachePath + ".resolve.deps"
	defer os.Remove(cacheFile)
	b, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, err
	}

	var cache depsdevAPICache
	dec := gob.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&cache); err != nil {
		return nil, err
	}

	pkgVers := make(map[resolve.PackageKey][]string)
	for vk := range cache.RequirementsCache {
		pk := resolve.PackageKey{
			Name:   vk.Name,
			System: resolve.System(vk.System),
		}
		pkgVers[pk] = append(pkgVers[pk], vk.Version)
	}

	return pkgVers, nil
}

// Copy the relevant cache format from the depsdev_api_cache
type depsdevAPICache struct {
	RequirementsCache map[struct {
		System  pb.System
		Name    string
		Version string
	}][]byte
}

func (t *depsdevAPICache) GobDecode(b []byte) error {
	type c depsdevAPICache
	dec := gob.NewDecoder(bytes.NewReader(b))

	return dec.Decode((*c)(t))
}

func makeUniverse(cl *client.DepsDevClient) (clienttest.ResolutionUniverse, error) {
	pkgs, err := getCachedVersions(cl)
	if err != nil {
		return clienttest.ResolutionUniverse{}, err
	}

	pks := maps.Keys(pkgs)
	slices.SortFunc(pks, func(a, b resolve.PackageKey) int { return a.Compare(b) })

	if len(pks) == 0 {
		return clienttest.ResolutionUniverse{}, errors.New("no packages found in cache")
	}
	// assume every package is the same system
	system := pks[0].System

	// Build the schema string.
	schema := &strings.Builder{}
	for _, pk := range pks {
		vers := pkgs[pk]
		slices.SortFunc(vers, system.Semver().Compare)
		fmt.Fprintln(schema, pk.Name)
		for _, v := range vers {
			fmt.Fprintln(schema, "\t"+v)
			reqs, err := cl.Requirements(context.Background(), resolve.VersionKey{
				PackageKey:  pk,
				Version:     v,
				VersionType: resolve.Concrete,
			})
			if err != nil {
				continue
			}
			for _, r := range reqs {
				// Don't bother writing Dev or Test dependencies.
				if r.Type.HasAttr(dep.Dev) || r.Type.HasAttr(dep.Test) {
					continue
				}
				str := r.Name + "@" + r.Version
				typeStr := typeString(r.Type)
				if typeStr != "" {
					str = typeStr + "|" + str
				}
				fmt.Fprintf(schema, "\t\t%s\n", str)
			}
		}
	}

	// Get all vulns for all versions of all packages.
	// It's easier to re-query this than to try use the vulnerability client's cache.
	var batchRequest osv.BatchedQuery
	batchRequest.Queries = make([]*osv.Query, len(pks))
	for i, pk := range pks {
		batchRequest.Queries[i] = &osv.Query{
			Package: osv.Package{
				Name:      pk.Name,
				Ecosystem: string(util.OSVEcosystem[pk.System]),
			},
		}
	}
	batchResponse, err := osv.MakeRequest(batchRequest)
	if err != nil {
		return clienttest.ResolutionUniverse{}, err
	}
	hydrated, err := osv.Hydrate(batchResponse)
	if err != nil {
		return clienttest.ResolutionUniverse{}, err
	}

	var vulns []models.Vulnerability
	for _, r := range hydrated.Results {
		vulns = append(vulns, r.Vulns...)
	}

	return clienttest.ResolutionUniverse{System: system.String(), Schema: schema.String(), Vulns: vulns}, nil
}

// These are just the relevant AttrKeys for our supported ecosystems.
var flagAttrs = [...]dep.AttrKey{dep.Dev, dep.Opt, dep.Test} // Keys without values
var valueAttrs = [...]dep.AttrKey{dep.Scope, dep.MavenClassifier, dep.MavenArtifactType, dep.MavenDependencyOrigin, dep.MavenExclusions, dep.KnownAs, dep.Selector}

func typeString(t dep.Type) string {
	// dep.Type.String() is not the same format as what the universe schema wants.
	// Manually construct the valid string.
	var parts []string
	for _, attr := range flagAttrs {
		if t.HasAttr(attr) {
			parts = append(parts, attr.String())
		}
	}

	for _, attr := range valueAttrs {
		if value, ok := t.GetAttr(attr); ok {
			parts = append(parts, attr.String(), strings.ReplaceAll(value, "|", ",")) // Must convert the MavenExclusions separator.
		}
	}

	return strings.Join(parts, " ")
}

func main() {
	cl, err := client.NewDepsDevClient(depsdev.DepsdevAPI)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	group := &errgroup.Group{}
	for _, filename := range os.Args[1:] {
		if io, err := manifest.GetReadWriter(filename, ""); err == nil {
			if remediation.SupportsRelax(io) {
				group.Go(func() error {
					err := doRelockRelax(cl, io, filename)
					if err != nil {
						return fmt.Errorf("failed to relock/relax %s: %w", filename, err)
					}

					return nil
				})
			}
			if remediation.SupportsOverride(io) {
				group.Go(func() error {
					err := doOverride(cl, io, filename)
					if err != nil {
						return fmt.Errorf("failed to relock/override %s: %w", filename, err)
					}

					return nil
				})
			}
		}
		if io, err := lockfile.GetReadWriter(filename); err == nil {
			if remediation.SupportsInPlace(io) {
				group.Go(func() error {
					err := doInPlace(cl, io, filename)
					if err != nil {
						return fmt.Errorf("failed to in-place update %s: %w", filename, err)
					}

					return nil
				})
			}
		}
	}
	if err := group.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	universe, err := makeUniverse(cl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error making universe: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "# Automatically generated by generate_mock_resolution_universe on %s. DO NOT EDIT.\n", time.Now().Format(time.RFC822))
	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	if err := enc.Encode(universe); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
