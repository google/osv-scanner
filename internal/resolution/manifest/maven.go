package manifest

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/pkg/lockfile"
)

const (
	OriginImport     = "import"
	OriginManagement = "management"
	OriginParent     = "parent"
	OriginPlugin     = "plugin"
	OriginProfile    = "profile"
)

func mavenRequirementKey(requirement resolve.RequirementVersion) RequirementKey {
	// Maven dependencies must have unique groupId:artifactId:type:classifier.
	artifactType, _ := requirement.Type.GetAttr(dep.MavenArtifactType)
	classifier, _ := requirement.Type.GetAttr(dep.MavenClassifier)

	return RequirementKey{
		PackageKey: requirement.PackageKey,
		EcosystemSpecific: struct{ ArtifactType, Classifier string }{
			ArtifactType: artifactType,
			Classifier:   classifier,
		},
	}
}

type MavenManifestIO struct {
	datasource.MavenRegistryAPIClient
}

func NewMavenManifestIO() MavenManifestIO {
	return MavenManifestIO{
		MavenRegistryAPIClient: *datasource.NewMavenRegistryAPIClient(datasource.MavenCentral),
	}
}

type MavenManifestSpecific struct {
	Properties             []PropertyWithOrigin
	OriginalRequirements   []DependencyWithOrigin
	RequirementsForUpdates []resolve.RequirementVersion // Requirements that we only need for updates
}

type PropertyWithOrigin struct {
	maven.Property
	Origin string // Origin indicates where the property comes from
}

type DependencyWithOrigin struct {
	maven.Dependency
	Origin string // Origin indicates where the property comes from
}

// TODO: handle profiles (activation and interpolation)
func (m MavenManifestIO) Read(df lockfile.DepFile) (Manifest, error) {
	ctx := context.Background()

	var project maven.Project
	if err := xml.NewDecoder(df).Decode(&project); err != nil {
		return Manifest{}, fmt.Errorf("failed to unmarshal project: %w", err)
	}
	properties := buildPropertiesWithOrigins(project)
	origRequirements := buildOriginalRequirements(project)

	var reqsForUpdates []resolve.RequirementVersion
	if project.Parent.GroupID != "" && project.Parent.ArtifactID != "" {
		reqsForUpdates = append(reqsForUpdates, resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   project.Parent.ProjectKey.Name(),
				},
				// Parent version is a concrete version, but we model parent as dependency here.
				VersionType: resolve.Requirement,
				Version:     string(project.Parent.Version),
			},
			Type: resolve.MavenDepType(maven.Dependency{}, OriginParent),
		})
	}

	// Merging parents data by parsing local parent pom.xml or fetching from upstream.
	if err := m.mergeParents(ctx, &project, project.Parent, 1, df.Path(), true); err != nil {
		return Manifest{}, fmt.Errorf("failed to merge parents: %w", err)
	}
	// Interpolate to resolve properties.
	if err := project.Interpolate(); err != nil {
		return Manifest{}, fmt.Errorf("failed to merge parents: %w", err)
	}

	// For dependency management imports, the importer will be replaced by the importees,
	// so add them to requirements first.
	for _, dep := range project.DependencyManagement.Dependencies {
		if dep.Scope == "import" && dep.Type == "pom" {
			reqsForUpdates = append(reqsForUpdates, makeRequirementVersion(dep, OriginManagement))
		}
	}

	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		root := maven.Parent{ProjectKey: maven.ProjectKey{GroupID: groupID, ArtifactID: artifactID, Version: version}}
		var result maven.Project
		if err := m.mergeParents(ctx, &result, root, 0, "", false); err != nil {
			return maven.DependencyManagement{}, err
		}
		// Interpolate to resolve properties.
		if err := result.Interpolate(); err != nil {
			return maven.DependencyManagement{}, err
		}

		return result.DependencyManagement, nil
	})

	var requirements []resolve.RequirementVersion
	groups := make(map[RequirementKey][]string)
	addRequirements := func(reqs *[]resolve.RequirementVersion, deps []maven.Dependency, origin string) {
		for _, dep := range deps {
			reqVer := makeRequirementVersion(dep, origin)
			*reqs = append(*reqs, reqVer)
			if dep.Scope != "" {
				reqKey := mavenRequirementKey(reqVer)
				groups[reqKey] = append(groups[reqKey], string(dep.Scope))
			}
		}
	}
	addRequirements(&requirements, project.Dependencies, "")
	addRequirements(&requirements, project.DependencyManagement.Dependencies, OriginManagement)

	// Requirements may not appear in the dependency graph but needs to be updated.
	for _, profile := range project.Profiles {
		addRequirements(&reqsForUpdates, profile.Dependencies, "")
		addRequirements(&reqsForUpdates, profile.DependencyManagement.Dependencies, OriginManagement)
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		addRequirements(&reqsForUpdates, plugin.Dependencies, "")
	}

	return Manifest{
		FilePath: df.Path(),
		Root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   project.ProjectKey.Name(),
				},
				VersionType: resolve.Concrete,
				Version:     string(project.Version),
			},
		},
		Requirements: requirements,
		Groups:       groups,
		EcosystemSpecific: MavenManifestSpecific{
			Properties:             properties,
			OriginalRequirements:   origRequirements,
			RequirementsForUpdates: reqsForUpdates,
		},
	}, nil
}

func buildPropertiesWithOrigins(project maven.Project) []PropertyWithOrigin {
	count := len(project.Properties.Properties)
	for _, prof := range project.Profiles {
		count += len(prof.Properties.Properties)
	}
	properties := make([]PropertyWithOrigin, 0, count)
	for _, prop := range project.Properties.Properties {
		properties = append(properties, PropertyWithOrigin{Property: prop})
	}
	for _, profile := range project.Profiles {
		for _, prop := range profile.Properties.Properties {
			properties = append(properties, PropertyWithOrigin{
				Property: prop,
				Origin:   mavenOrigin(OriginProfile, string(profile.ID)),
			})
		}
	}

	return properties
}

func buildOriginalRequirements(project maven.Project) []DependencyWithOrigin {
	var dependencies []DependencyWithOrigin //nolint:prealloc
	if project.Parent.GroupID != "" && project.Parent.ArtifactID != "" {
		dependencies = append(dependencies, DependencyWithOrigin{
			Dependency: maven.Dependency{
				GroupID:    project.Parent.GroupID,
				ArtifactID: project.Parent.ArtifactID,
				Version:    project.Parent.Version,
			},
			Origin: OriginParent,
		})
	}
	for _, d := range project.Dependencies {
		dependencies = append(dependencies, DependencyWithOrigin{Dependency: d})
	}
	for _, d := range project.DependencyManagement.Dependencies {
		dependencies = append(dependencies, DependencyWithOrigin{
			Dependency: d,
			Origin:     OriginManagement,
		})
	}
	for _, prof := range project.Profiles {
		for _, d := range prof.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(OriginProfile, string(prof.ID)),
			})
		}
		for _, d := range prof.DependencyManagement.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(OriginProfile, string(prof.ID), OriginManagement),
			})
		}
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		for _, d := range plugin.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(OriginPlugin, plugin.ProjectKey.Name()),
			})
		}
	}

	return dependencies
}

// To avoid indefinite loop when fetching parents,
// set a limit on the number of parents.
const MaxParent = 100

func (m MavenManifestIO) mergeParents(ctx context.Context, result *maven.Project, current maven.Parent, start int, path string, allowLocal bool) error {
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
			// Once we fetch a parent pom.xml from upstream, we should not allow
			// parsing parent pom.xml locally anymore.
			allowLocal = false
			var err error
			proj, err = m.MavenRegistryAPIClient.GetProject(ctx, string(current.GroupID), string(current.ArtifactID), string(current.Version))
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

	return nil
}

// For dependencies in profiles and plugins, we use origin to indicate where they are from.
// The origin is in the format prefix@identifier[@postfix] (where @ is the separator):
//   - prefix indicates it is from profile or plugin
//   - identifier to locate the profile/plugin which is profile ID or plugin name
//   - (optional) suffix indicates if this is a dependency management
func makeRequirementVersion(dep maven.Dependency, origin string) resolve.RequirementVersion {
	// Treat test & optional dependencies as regular dependencies to force the resolver to resolve them.
	if dep.Scope == "test" {
		dep.Scope = ""
	}
	dep.Optional = ""

	return resolve.RequirementVersion{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.Maven,
				Name:   dep.Name(),
			},
			VersionType: resolve.Requirement,
			Version:     string(dep.Version),
		},
		Type: resolve.MavenDepType(dep, origin),
	}
}

func mavenOrigin(list ...string) string {
	result := ""
	for _, str := range list {
		if result != "" && str != "" {
			result += "@"
		}
		if str != "" {
			result += str
		}
	}

	return result
}

func projectStartElement(raw string) string {
	start := strings.Index(raw, "<project")
	if start < 0 {
		return ""
	}
	end := strings.Index(raw[start:], ">")
	if end < 0 {
		return ""
	}

	return raw[start : start+end+1]
}

// MavenPropertyPatches represent the properties to be updated, which
// is a map of properties of each origin.
type MavenPropertyPatches map[string]map[string]string // origin -> tag -> value

func (MavenManifestIO) Write(df lockfile.DepFile, w io.Writer, patch ManifestPatch) error {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(df); err != nil {
		return fmt.Errorf("failed to read from DepFile: %w", err)
	}

	dec := xml.NewDecoder(bytes.NewReader(buf.Bytes()))
	enc := xml.NewEncoder(w)

	patches := make(map[string][]DependencyPatch)
	for _, changedDep := range patch.Deps {
		_, o, err := resolve.MavenDepTypeToDependency(changedDep.Type)
		if err != nil {
			return fmt.Errorf("depTypeToMavenDependency: %w", err)
		}
		patches[o] = append(patches[o], changedDep)
	}

	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("getting token: %w", err)
		}

		if tt, ok := token.(xml.StartElement); ok {
			if tt.Name.Local == "project" {
				type RawProject struct {
					InnerXML string `xml:",innerxml"`
				}
				var rawProj RawProject
				if err := dec.DecodeElement(&rawProj, &tt); err != nil {
					return err
				}

				// xml.EncodeToken writes a start element with its all name spaces.
				// It's very common to have a start project element with a few name spaces in Maven.
				// Thus this would cause a big diff when we try to encode the start element of project.

				// We first capture the raw start element string and write it.
				projectStart := projectStartElement(buf.String())
				if projectStart == "" {
					return errors.New("unable to get start element of project")
				}
				if _, err := w.Write([]byte(projectStart)); err != nil {
					return fmt.Errorf("writing start element of project: %w", err)
				}

				properties, ok := patch.EcosystemSpecific.(MavenPropertyPatches)
				if !ok {
					return errors.New("cannot convert ecosystem specific information to Maven properties")
				}
				// Then we update the project by passing the innerXML and name spaces are not passed.
				if err := updateProject(enc, rawProj.InnerXML, "", "", patches, properties); err != nil {
					return fmt.Errorf("updating project: %w", err)
				}

				// Finally we write the end element of project.
				if _, err := w.Write([]byte("</project>")); err != nil {
					return fmt.Errorf("writing start element of project: %w", err)
				}

				continue
			}
		}
		if err := enc.EncodeToken(token); err != nil {
			return err
		}
		if err := enc.Flush(); err != nil {
			return err
		}
	}

	return nil
}
func updateProject(enc *xml.Encoder, raw, prefix, id string, patches map[string][]DependencyPatch, properties MavenPropertyPatches) error {
	dec := xml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if tt, ok := token.(xml.StartElement); ok {
			switch tt.Name.Local {
			case "parent":
				type RawParent struct {
					maven.ProjectKey
					InnerXML string `xml:",innerxml"`
				}
				var rawParent RawParent
				if err := dec.DecodeElement(&rawParent, &tt); err != nil {
					return err
				}
				req := string(rawParent.Version)
				deps, ok := patches["parent"]
				if ok {
					req = deps[0].NewRequire
				}
				if err := updateString(enc, "<parent>"+rawParent.InnerXML+"</parent>", map[string]string{"version": req}); err != nil {
					return fmt.Errorf("updating parent: %w", err)
				}

				continue
			case "properties":
				type RawProperties struct {
					InnerXML string `xml:",innerxml"`
				}
				var rawProperties RawProperties
				if err := dec.DecodeElement(&rawProperties, &tt); err != nil {
					return err
				}
				if err := updateString(enc, "<properties>"+rawProperties.InnerXML+"</properties>", properties[mavenOrigin(prefix, id)]); err != nil {
					return fmt.Errorf("updating properties: %w", err)
				}

				continue
			case "profile":
				if prefix != "" || id != "" {
					// Skip updating if prefix or id is set to avoid infinite recursion
					break
				}
				type RawProfile struct {
					maven.Profile
					InnerXML string `xml:",innerxml"`
				}
				var rawProfile RawProfile
				if err := dec.DecodeElement(&rawProfile, &tt); err != nil {
					return err
				}
				if err := updateProject(enc, "<profile>"+rawProfile.InnerXML+"</profile>", OriginProfile, string(rawProfile.ID), patches, properties); err != nil {
					return fmt.Errorf("updating profile: %w", err)
				}

				continue
			case "plugin":
				if prefix != "" || id != "" {
					// Skip updating if prefix or id is set to avoid infinite recursion
					break
				}
				type RawPlugin struct {
					maven.Plugin
					InnerXML string `xml:",innerxml"`
				}
				var rawPlugin RawPlugin
				if err := dec.DecodeElement(&rawPlugin, &tt); err != nil {
					return err
				}
				if err := updateProject(enc, "<plugin>"+rawPlugin.InnerXML+"</plugin>", OriginPlugin, rawPlugin.ProjectKey.Name(), patches, properties); err != nil {
					return fmt.Errorf("updating profile: %w", err)
				}

				continue
			case "dependencyManagement":
				type RawDependencyManagement struct {
					maven.DependencyManagement
					InnerXML string `xml:",innerxml"`
				}
				var rawDepMgmt RawDependencyManagement
				if err := dec.DecodeElement(&rawDepMgmt, &tt); err != nil {
					return err
				}
				if err := updateDependency(enc, "<dependencyManagement>"+rawDepMgmt.InnerXML+"</dependencyManagement>", patches[mavenOrigin(prefix, id, OriginManagement)]); err != nil {
					return fmt.Errorf("updating dependency management: %w", err)
				}

				continue
			case "dependencies":
				type RawDependencies struct {
					Dependencies []maven.Dependency `xml:"dependencies"`
					InnerXML     string             `xml:",innerxml"`
				}
				var rawDeps RawDependencies
				if err := dec.DecodeElement(&rawDeps, &tt); err != nil {
					return err
				}
				if err := updateDependency(enc, "<dependencies>"+rawDeps.InnerXML+"</dependencies>", patches[mavenOrigin(prefix, id)]); err != nil {
					return fmt.Errorf("updating dependencies: %w", err)
				}

				continue
			}
		}
		if err := enc.EncodeToken(token); err != nil {
			return err
		}
	}

	return enc.Flush()
}
func updateDependency(enc *xml.Encoder, raw string, patches []DependencyPatch) error {
	dec := xml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if tt, ok := token.(xml.StartElement); ok {
			if tt.Name.Local == "dependency" {
				type RawDependency struct {
					maven.Dependency
					InnerXML string `xml:",innerxml"`
				}
				var rawDep RawDependency
				if err := dec.DecodeElement(&rawDep, &tt); err != nil {
					return err
				}
				req := string(rawDep.Version)
				for _, patch := range patches {
					d, _, err := resolve.MavenDepTypeToDependency(patch.Type)
					if err != nil {
						return fmt.Errorf("depTypeToMavenDependency: %w", err)
					}
					// A Maven dependency key consists of Type and Classifier together with GroupID and ArtifactID.
					if patch.Pkg.Name == rawDep.Dependency.Name() && d.Type == rawDep.Type && d.Classifier == rawDep.Classifier {
						req = patch.NewRequire
					}
				}
				// xml.EncodeElement writes all empty elements and may not follow the existing format.
				// Passing the innerXML can help to keep the original format.
				if err := updateString(enc, "<dependency>"+rawDep.InnerXML+"</dependency>", map[string]string{"version": req}); err != nil {
					return fmt.Errorf("updating dependency: %w", err)
				}

				continue
			}
		}
		if err := enc.EncodeToken(token); err != nil {
			return err
		}
	}

	return enc.Flush()
}
func updateString(enc *xml.Encoder, raw string, values map[string]string) error {
	dec := xml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if tt, ok := token.(xml.StartElement); ok {
			if value, ok2 := values[tt.Name.Local]; ok2 {
				var str string
				if err := dec.DecodeElement(&str, &tt); err != nil {
					return err
				}
				if err := enc.EncodeElement(value, tt); err != nil {
					return err
				}

				continue
			}
		}
		if err := enc.EncodeToken(token); err != nil {
			return err
		}
	}

	return enc.Flush()
}
