// Package pomxmlnet extracts Maven's pom.xml format with transitive dependency resolution.
package pomxmlnet

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"golang.org/x/exp/maps"

	mavenresolve "deps.dev/util/resolve/maven"
	mavenutil "github.com/google/osv-scanner/internal/utility/maven"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/datasource"
)

// Extractor extracts osv packages from osv-scanner json output.
type Extractor struct {
	client.DependencyClient
	*datasource.MavenRegistryAPIClient
}

// Name of the extractor.
func (e Extractor) Name() string { return "osv/pomxmlnet" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: true,
	}
}

// FileRequired never returns true, as this is for the osv-scanner json output.
func (e Extractor) FileRequired(path string, _ fs.FileInfo) bool {
	return filepath.Base(path) == "pom.xml"
}

// Extract extracts packages from yarn.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var project maven.Project
	if err := datasource.NewMavenDecoder(input.Reader).Decode(&project); err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
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
	if err := mavenutil.MergeParents(ctx, e.MavenRegistryAPIClient, &project, project.Parent, 1, input.Path, true); err != nil {
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

	client.PreFetch(ctx, overrideClient, reqs, input.Path)
	g, err := resolver.Resolve(ctx, root.VersionKey)
	if err != nil {
		return nil, fmt.Errorf("failed resolving %v: %w", root, err)
	}
	for i, e := range g.Edges {
		e.Type = dep.Type{}
		g.Edges[i] = e
	}

	details := map[string]*extractor.Inventory{}
	for i := 1; i < len(g.Nodes); i++ {
		// Ignore the first node which is the root.
		node := g.Nodes[i]
		depGroups := []string{}
		inventory := extractor.Inventory{
			Name:    node.Version.Name,
			Version: node.Version.Version,
			// TODO(rexpan): Add merged paths in here as well
			Locations: []string{input.Path},
		}
		// We are only able to know dependency groups of direct dependencies but
		// not transitive dependencies because the nodes in the resolve graph does
		// not have the scope information.
		for _, dep := range project.Dependencies {
			if dep.Name() != inventory.Name {
				continue
			}
			if dep.Scope != "" && dep.Scope != "compile" {
				depGroups = append(depGroups, string(dep.Scope))
			}
		}
		inventory.Metadata = osv.DepGroupMetadata{
			DepGroupVals: depGroups,
		}
		details[inventory.Name] = &inventory
	}

	return maps.Values(details), nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeMaven,
		Name:    i.Name,
		Version: i.Version,
	}
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(_ *extractor.Inventory) []string { return []string{} }

// Ecosystem returns the OSV ecosystem ('npm') of the software extracted by this extractor.
func (e Extractor) Ecosystem(_ *extractor.Inventory) string {
	return "Maven"
}

var _ filesystem.Extractor = Extractor{}
