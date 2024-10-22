package maven

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"deps.dev/util/maven"
	"github.com/google/osv-scanner/internal/resolution/datasource"
)

const (
	OriginManagement = "management"
	OriginParent     = "parent"
	OriginPlugin     = "plugin"
	OriginProfile    = "profile"
)

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
func MergeParents(ctx context.Context, mavenClient *datasource.MavenRegistryAPIClient, result *maven.Project, current maven.Parent, start int, path string, allowLocal bool) error {
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
		if parentPath := ParentPOMPath(currentPath, string(current.RelativePath)); allowLocal && parentPath != "" {
			currentPath = parentPath
			f, err := os.Open(parentPath)
			if err != nil {
				return fmt.Errorf("failed to open parent file %s: %w", parentPath, err)
			}
			err = datasource.NewMavenDecoder(f).Decode(&proj)
			f.Close()
			if err != nil {
				return fmt.Errorf("failed to unmarshal project: %w", err)
			}
			if ProjectKey(proj) == current.ProjectKey && proj.Packaging == "pom" {
				// Only mark parent is found when the identifiers and packaging are exptected.
				parentFound = true
			}
		}
		if !parentFound {
			// Once we fetch a parent pom.xml from upstream, we should not
			// allow parsing parent pom.xml locally anymore.
			allowLocal = false

			var err error
			if proj, err = mavenClient.GetProject(ctx, string(current.GroupID), string(current.ArtifactID), string(current.Version)); err != nil {
				return fmt.Errorf("failed to get Maven project %s:%s:%s: %w", current.GroupID, current.ArtifactID, current.Version, err)
			}
			if n > 0 && proj.Packaging != "pom" {
				// A parent project should only be of "pom" packaging type.
				return fmt.Errorf("invalid packaging for parent project %s", proj.Packaging)
			}
			if ProjectKey(proj) != current.ProjectKey {
				// The identifiers in parent does not match what we want.
				return fmt.Errorf("parent identifiers mismatch: %v, expect %v", proj.ProjectKey, current.ProjectKey)
			}
		}
		// Empty JDK and ActivationOS indicates merging the default profiles.
		if err := result.MergeProfiles("", maven.ActivationOS{}); err != nil {
			return fmt.Errorf("failed to merge profiles: %w", err)
		}
		for _, repo := range proj.Repositories {
			if err := mavenClient.AddRegistry(string(repo.URL)); err != nil {
				return fmt.Errorf("failed to add registry %s: %w", repo.URL, err)
			}
		}
		result.MergeParent(proj)
		current = proj.Parent
	}
	// Interpolate the project to resolve the properties.
	return result.Interpolate()
}

// ProjectKey returns a project key with empty groupId/version
// filled by corresponding fields in parent.
func ProjectKey(proj maven.Project) maven.ProjectKey {
	if proj.GroupID == "" {
		proj.GroupID = proj.Parent.GroupID
	}
	if proj.Version == "" {
		proj.Version = proj.Parent.Version
	}

	return proj.ProjectKey
}

// Maven looks for the parent POM first in 'relativePath',
// then the local repository '../pom.xml',
// and lastly in the remote repo.
func ParentPOMPath(currentPath, relativePath string) string {
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

// GetDependencyManagement returns managed dependencies in the specified Maven project by fetching remote pom.xml.
func GetDependencyManagement(ctx context.Context, client *datasource.MavenRegistryAPIClient, groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
	root := maven.Parent{ProjectKey: maven.ProjectKey{GroupID: groupID, ArtifactID: artifactID, Version: version}}
	var result maven.Project
	// To get dependency management from another project, we need the
	// project with parents merged, so we call MergeParents by passing
	// an empty project.
	if err := MergeParents(ctx, client.WithoutRegistries(), &result, root, 0, "", false); err != nil {
		return maven.DependencyManagement{}, err
	}

	return result.DependencyManagement, nil
}
