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

const (
	OriginManagement = "management"
	OriginParent     = "parent"
	OriginPlugin     = "plugin"
	OriginProfile    = "profile"
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
	if err := MergeMavenParents(ctx, e.MavenRegistryAPIClient, &project, project.Parent, 1, f.Path(), true); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("failed to merge parents: %w", err)
	}
	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		root := maven.Parent{ProjectKey: maven.ProjectKey{GroupID: groupID, ArtifactID: artifactID, Version: version}}
		var result maven.Project
		if err := MergeMavenParents(ctx, e.MavenRegistryAPIClient, &result, root, 0, f.Path(), false); err != nil {
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
			Type: resolve.MavenDepType(d, OriginManagement),
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

// MergeMavenParents parses local accessible parent pom.xml or fetches it from
// upstream, merges into root project, then interpolate the properties.
// result holds the merged Maven project.
// current holds the current parent project to merge.
// start indicates the index of the current parent project, which is used to
// check if the packaging has to be `pom`.
// allowLocal indicates whether parsing local parent pom.xml is allowed.
// path holds the path to the current pom.xml, which is used to compute the
// relative path of parent.
func MergeMavenParents(ctx context.Context, mavenClient datasource.MavenRegistryAPIClient, result *maven.Project, current maven.Parent, start int, path string, allowLocal bool) error {
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
		parentFound := false
		if parentPath := MavenParentPOMPath(currentPath, string(current.RelativePath)); allowLocal && parentPath != "" {
			currentPath = parentPath
			f, err := os.Open(parentPath)
			if err != nil {
				return fmt.Errorf("failed to open parent file %s: %w", parentPath, err)
			}
			if err := xml.NewDecoder(f).Decode(&proj); err != nil {
				return fmt.Errorf("failed to unmarshal project: %w", err)
			}
			if proj.GroupID == "" {
				// A project may inherit groupId from parent
				proj.GroupID = proj.Parent.GroupID
			}
			if proj.ProjectKey == current.ProjectKey && proj.Packaging == "pom" {
				// Only mark parent is found when the identifiers and packaging are exptected.
				parentFound = true
			}
		}
		if !parentFound {
			// Once we fetch a parent pom.xml from upstream, we should not
			// allow parsing parent pom.xml locally anymore.
			allowLocal = false

			var err error
			proj, err = mavenClient.GetProject(ctx, string(current.GroupID), string(current.ArtifactID), string(current.Version))
			if err != nil {
				return fmt.Errorf("failed to get Maven project %s:%s:%s: %w", current.GroupID, current.ArtifactID, current.Version, err)
			}
			if n > 0 && proj.Packaging != "pom" {
				// A parent project should only be of "pom" packaging type.
				return fmt.Errorf("invalid packaging for parent project %s", proj.Packaging)
			}
			if proj.GroupID == "" {
				// A project may inherit groupId from parent
				proj.GroupID = proj.Parent.GroupID
			}
			if proj.ProjectKey != current.ProjectKey {
				// The identifiers in parent does not match what we want.
				return fmt.Errorf("parent identifiers mismatch: %v, expect %v", proj.ProjectKey, current.ProjectKey)
			}
		}
		// Empty JDK and ActivationOS indicates merging the default profiles.
		if err := result.MergeProfiles("", maven.ActivationOS{}); err != nil {
			return err
		}
		result.MergeParent(proj)
		current = proj.Parent
	}
	// Interpolate the project to resolve the properties.
	return result.Interpolate()
}

// Maven looks for the parent POM first in 'relativePath',
// then the local repository '../pom.xml',
// and lastly in the remote repo.
func MavenParentPOMPath(currentPath, relativePath string) string {
	if relativePath == "" {
		relativePath = "../pom.xml"
	}
	path := filepath.Join(filepath.Dir(currentPath), relativePath)
	if info, err := os.Stat(path); err == nil {
		if !info.IsDir() {
			return path
		}
		// Current path is a directory, so look for pom.xml in the directory.
		path = filepath.Join(path, "pom.xml")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func ParseMavenWithResolver(depClient client.DependencyClient, mavenClient datasource.MavenRegistryAPIClient, pathToLockfile string) ([]lockfile.PackageDetails, error) {
	f, err := lockfile.OpenLocalDepFile(pathToLockfile)
	if err != nil {
		return []lockfile.PackageDetails{}, err
	}
	defer f.Close()

	return MavenResolverExtractor{DependencyClient: depClient, MavenRegistryAPIClient: mavenClient}.Extract(f)
}
