package manifest

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	mavenresolve "deps.dev/util/resolve/maven"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/resolution/util"
	"github.com/google/osv-scanner/pkg/lockfile"
	"golang.org/x/exp/maps"
)

type MavenResolverExtractor struct {
	client.DependencyClient
	datasource.MavenRegistryAPIClient
}

func (e MavenResolverExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pom.xml"
}

func (e MavenResolverExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	ctx := context.Background()

	var project maven.Project
	if err := xml.NewDecoder(f).Decode(&project); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	// Merging parents data by parsing local parent pom.xml or fetching from upstream.
	if err := e.mergeParents(ctx, &project, project.Parent, 1, true, f.Path()); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("failed to merge parents: %w", err)
	}
	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		root := maven.Parent{ProjectKey: maven.ProjectKey{GroupID: groupID, ArtifactID: artifactID, Version: version}}
		var result maven.Project
		if err := e.mergeParents(ctx, &result, root, 0, false, f.Path()); err != nil {
			return maven.DependencyManagement{}, err
		}

		return result.DependencyManagement, nil
	})

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
	reqs := make([]resolve.RequirementVersion, len(project.Dependencies))
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
	overrideClient.AddVersion(root, reqs)

	g, err := resolver.Resolve(ctx, root.VersionKey)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("failed resolving %v: %w", root, err)
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

// MaxParent sets a limit on the number of parents to avoid indefinite loop.
const MaxParent = 100

// mergeParents parses local accessible parent pom.xml or fetches it from
// upstream, merges into root project, then interpolate the properties.
// result holds the merged Maven project.
// current holds the current parent project to merge.
// start indicates the index of the current parent project, which is used to
// check if the packaging has to be `pom`.
// allowLocal indicates whether parsing local parent pom.xml is allowed.
// path holds the path to the current pom.xml, which is used to compute the
// relative path of parent.
func (e MavenResolverExtractor) mergeParents(ctx context.Context, result *maven.Project, current maven.Parent, start int, allowLocal bool, path string) error {
	currentPath := path
	visited := make(map[maven.ProjectKey]bool, MaxParent)
	for n := start; n < MaxParent; n++ {
		if current.GroupID == "" || current.ArtifactID == "" || current.Version == "" {
			break
		}
		if visited[current.ProjectKey] {
			// A cycle of parents is detected
			return errors.New("a cycle of parents is detected")
		}
		visited[current.ProjectKey] = true

		var proj maven.Project
		if allowLocal && current.RelativePath != "" {
			currentPath = filepath.Join(filepath.Dir(currentPath), string(current.RelativePath))
			if filepath.Base(currentPath) != "pom.xml" {
				// If the base is not pom.xml, this path is a directory but not a file.
				currentPath = filepath.Join(currentPath, "pom.xml")
			}
			f, err := os.Open(currentPath)
			if err != nil {
				return fmt.Errorf("failed to open parent file %s: %w", current.RelativePath, err)
			}
			if err := xml.NewDecoder(f).Decode(&proj); err != nil {
				return fmt.Errorf("failed to unmarshal project: %w", err)
			}
		} else {
			// Once we fetch a parent pom.xml from upstream, we should not
			// allow parsing parent pom.xml locally anymore.
			allowLocal = false

			var err error
			proj, err = e.MavenRegistryAPIClient.GetProject(ctx, string(current.GroupID), string(current.ArtifactID), string(current.Version))
			if err != nil {
				return fmt.Errorf("failed to get Maven project %s:%s:%s: %w", current.GroupID, current.ArtifactID, current.Version, err)
			}
			if n > 0 && proj.Packaging != "pom" {
				// A parent project should only be of "pom" packaging type.
				return fmt.Errorf("invalid packaging for parent project %s", proj.Packaging)
			}
		}
		result.MergeParent(proj)
		current = proj.Parent
	}
	// Interpolate the project to resolve the properties.
	return result.Interpolate()
}

func ParseMavenWithResolver(depClient client.DependencyClient, mavenClient datasource.MavenRegistryAPIClient, pathToLockfile string) ([]lockfile.PackageDetails, error) {
	f, err := lockfile.OpenLocalDepFile(pathToLockfile)
	if err != nil {
		return []lockfile.PackageDetails{}, err
	}
	defer f.Close()

	return MavenResolverExtractor{DependencyClient: depClient, MavenRegistryAPIClient: mavenClient}.Extract(f)
}
