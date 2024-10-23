package manifest

import (
	"context"
	"fmt"
	"path/filepath"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	mavenresolve "deps.dev/util/resolve/maven"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/resolution/util"
	mavenutil "github.com/google/osv-scanner/internal/utility/maven"
	"github.com/google/osv-scanner/pkg/lockfile"
	"golang.org/x/exp/maps"
)

type MavenResolverExtractor struct {
	client.DependencyClient
	*datasource.MavenRegistryAPIClient
}

func (e MavenResolverExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pom.xml"
}

func (e MavenResolverExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	ctx := context.Background()

	var project maven.Project
	if err := datasource.NewMavenDecoder(f).Decode(&project); err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	// Empty JDK and ActivationOS indicates merging the default profiles.
	if err := project.MergeProfiles("", maven.ActivationOS{}); err != nil {
		return nil, fmt.Errorf("failed to merge profiles: %w", err)
	}
	for _, repo := range project.Repositories {
		if err := e.MavenRegistryAPIClient.AddRegistry(string(repo.URL)); err != nil {
			return nil, fmt.Errorf("failed to add registry %s: %w", repo.URL, err)
		}
	}
	// Merging parents data by parsing local parent pom.xml or fetching from upstream.
	if err := mavenutil.MergeParents(ctx, e.MavenRegistryAPIClient, &project, project.Parent, 1, f.Path(), true); err != nil {
		return nil, fmt.Errorf("failed to merge parents: %w", err)
	}
	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		return mavenutil.GetDependencyManagement(ctx, e.MavenRegistryAPIClient, groupID, artifactID, version)
	})

	if registries := e.MavenRegistryAPIClient.GetRegistries(); len(registries) > 0 {
		clientRegs := make([]client.Registry, len(registries))
		for i, reg := range registries {
			clientRegs[i] = client.Registry{URL: reg}
		}
		if err := e.DependencyClient.AddRegistries(clientRegs); err != nil {
			return nil, err
		}
	}
	overrideClient := client.NewOverrideClient(e.DependencyClient)
	resolver := mavenresolve.NewResolver(overrideClient)

	// Resolve the dependencies.
	root := resolve.Version{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.Maven,
				Name:   project.ProjectKey.Name(),
			},
			VersionType: resolve.Concrete,
			Version:     string(project.Version),
		}}
	reqs := make([]resolve.RequirementVersion, len(project.Dependencies)+len(project.DependencyManagement.Dependencies))
	for i, d := range project.Dependencies {
		reqs[i] = resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   d.Name(),
				},
				VersionType: resolve.Requirement,
				Version:     string(d.Version),
			},
			Type: resolve.MavenDepType(d, ""),
		}
	}
	for i, d := range project.DependencyManagement.Dependencies {
		reqs[len(project.Dependencies)+i] = resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   d.Name(),
				},
				VersionType: resolve.Requirement,
				Version:     string(d.Version),
			},
			Type: resolve.MavenDepType(d, mavenutil.OriginManagement),
		}
	}
	overrideClient.AddVersion(root, reqs)

	client.PreFetch(ctx, overrideClient, reqs, f.Path())
	g, err := resolver.Resolve(ctx, root.VersionKey)
	if err != nil {
		return nil, fmt.Errorf("failed resolving %v: %w", root, err)
	}
	for i, e := range g.Edges {
		e.Type = dep.Type{}
		g.Edges[i] = e
	}

	details := map[string]lockfile.PackageDetails{}
	for i := 1; i < len(g.Nodes); i++ {
		// Ignore the first node which is the root.
		node := g.Nodes[i]
		pkgDetails := util.VKToPackageDetails(node.Version)
		// We are only able to know dependency groups of direct dependencies but
		// not transitive dependencies because the nodes in the resolve graph does
		// not have the scope information.
		for _, dep := range project.Dependencies {
			if dep.Name() != pkgDetails.Name {
				continue
			}
			if dep.Scope != "" && dep.Scope != "compile" {
				pkgDetails.DepGroups = append(pkgDetails.DepGroups, string(dep.Scope))
			}
		}
		details[pkgDetails.Name] = pkgDetails
	}

	return maps.Values(details), nil
}

func ParseMavenWithResolver(depClient client.DependencyClient, mavenClient *datasource.MavenRegistryAPIClient, pathToLockfile string) ([]lockfile.PackageDetails, error) {
	f, err := lockfile.OpenLocalDepFile(pathToLockfile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return MavenResolverExtractor{
		DependencyClient:       depClient,
		MavenRegistryAPIClient: mavenClient,
	}.Extract(f)
}
