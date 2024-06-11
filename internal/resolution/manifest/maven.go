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
	Properties                 []PropertyWithOrigin
	RequirementsWithProperties []resolve.RequirementVersion
	RequirementsFromOtherPOMs  []resolve.RequirementVersion // Requirements that we cannot modify directly
}

type PropertyWithOrigin struct {
	maven.Property
	Origin string // Origin indicates where the property comes from
}

// TODO: handle profiles (activation and interpolation)
func (m MavenManifestIO) Read(df lockfile.DepFile) (Manifest, error) {
	ctx := context.Background()

	var reqsWithProps []resolve.RequirementVersion
	requirementOrigins := make(map[maven.DependencyKey]string)
	addRequirementOrigins := func(deps []maven.Dependency, origin string) {
		for _, dep := range deps {
			key := dep.Key()
			if _, ok := requirementOrigins[key]; !ok {
				requirementOrigins[key] = origin
			}
			if dep.Version.ContainsProperty() {
				// We only need the original import if the version contains any property.
				reqsWithProps = append(reqsWithProps, makeRequirementVersion(dep, origin))
			}
		}
	}
	addAllRequirements := func(project maven.Project, origin string) {
		addRequirementOrigins(project.Dependencies, origin)
		addRequirementOrigins(project.DependencyManagement.Dependencies, mavenOrigin(origin, OriginManagement))
		for _, profile := range project.Profiles {
			addRequirementOrigins(profile.Dependencies, mavenOrigin(origin, OriginProfile, string(profile.ID)))
			addRequirementOrigins(profile.DependencyManagement.Dependencies, mavenOrigin(origin, OriginProfile, string(profile.ID), OriginManagement))
		}
		for _, plugin := range project.Build.PluginManagement.Plugins {
			addRequirementOrigins(plugin.Dependencies, mavenOrigin(origin, OriginPlugin, plugin.ProjectKey.Name()))
		}
	}

	interpolate := func(project *maven.Project) error {
		// Interpolating can change a dependency's key if it contained properties.
		// If it is changed we need to update the requirementOrigins map with the new key.
		allKeys := func() []maven.DependencyKey {
			// Get all the dependencyKeys of the project.
			// This order shouldn't change after calling Interpolate.
			var keys []maven.DependencyKey
			for _, dep := range project.Dependencies {
				keys = append(keys, dep.Key())
			}
			for _, dep := range project.DependencyManagement.Dependencies {
				keys = append(keys, dep.Key())
			}
			for _, profile := range project.Profiles {
				for _, dep := range profile.Dependencies {
					keys = append(keys, dep.Key())
				}
				for _, dep := range profile.DependencyManagement.Dependencies {
					keys = append(keys, dep.Key())
				}
			}
			for _, plugin := range project.Build.PluginManagement.Plugins {
				for _, dep := range plugin.Dependencies {
					keys = append(keys, dep.Key())
				}
			}

			return keys
		}

		prevKeys := allKeys()
		if err := project.Interpolate(); err != nil {
			return err
		}

		newKeys := allKeys()
		if len(prevKeys) != len(newKeys) {
			// The length can change if properties fail to resolve, which should be rare.
			// It's difficult to determine which dependencies were removed in these cases, so just error.
			return errors.New("number of dependencies changed after interpolation")
		}

		for i, prevKey := range prevKeys {
			newKey := newKeys[i]
			if newKey != prevKey {
				requirementOrigins[newKey] = requirementOrigins[prevKey]
			}
		}

		return nil
	}

	var project maven.Project
	if err := xml.NewDecoder(df).Decode(&project); err != nil {
		return Manifest{}, fmt.Errorf("failed to unmarshal project: %w", err)
	}
	addAllRequirements(project, "")

	// Merging parents data by parsing local parent pom.xml or fetching from upstream.
	if err := m.mergeParents(ctx, &project, project.Parent, 1, df.Path(), true, addAllRequirements, OriginParent); err != nil {
		return Manifest{}, fmt.Errorf("failed to merge parents: %w", err)
	}
	// Interpolate to resolve properties.
	if err := interpolate(&project); err != nil {
		return Manifest{}, fmt.Errorf("failed to merge parents: %w", err)
	}

	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		root := maven.Parent{ProjectKey: maven.ProjectKey{GroupID: groupID, ArtifactID: artifactID, Version: version}}
		var result maven.Project
		if err := m.mergeParents(ctx, &result, root, 0, "", false, addAllRequirements, OriginImport); err != nil {
			return maven.DependencyManagement{}, err
		}
		// Interpolate to resolve properties.
		if err := interpolate(&result); err != nil {
			return maven.DependencyManagement{}, err
		}

		return result.DependencyManagement, nil
	})

	count := len(project.Properties.Properties)
	for _, prof := range project.Profiles {
		count += len(prof.Properties.Properties)
	}
	properties := make([]PropertyWithOrigin, 0, count)
	for _, prop := range project.Properties.Properties {
		properties = append(properties, PropertyWithOrigin{Property: prop})
	}

	var requirements []resolve.RequirementVersion
	var otherRequirements []resolve.RequirementVersion
	groups := make(map[RequirementKey][]string)
	addRequirements := func(deps []maven.Dependency) {
		for _, dep := range deps {
			origin := requirementOrigins[dep.Key()]
			reqVer := makeRequirementVersion(dep, origin)
			if strings.HasPrefix(origin, OriginParent+"@") || strings.HasPrefix(origin, OriginImport) {
				otherRequirements = append(otherRequirements, reqVer)
			} else {
				requirements = append(requirements, reqVer)
			}
			if dep.Scope != "" {
				reqKey := mavenRequirementKey(reqVer)
				groups[reqKey] = append(groups[reqKey], string(dep.Scope))
			}
		}
	}
	if project.Parent.GroupID != "" && project.Parent.ArtifactID != "" {
		requirements = append(requirements, resolve.RequirementVersion{
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
	addRequirements(project.Dependencies)
	addRequirements(project.DependencyManagement.Dependencies)
	for _, profile := range project.Profiles {
		addRequirements(profile.Dependencies)
		addRequirements(profile.DependencyManagement.Dependencies)
		for _, prop := range profile.Properties.Properties {
			properties = append(properties, PropertyWithOrigin{
				Property: prop,
				Origin:   mavenOrigin(OriginProfile, string(profile.ID)),
			})
		}
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		addRequirements(plugin.Dependencies)
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
			Properties:                 properties,
			RequirementsWithProperties: reqsWithProps,
			RequirementsFromOtherPOMs:  otherRequirements,
		},
	}, nil
}

// To avoid indefinite loop when fetching parents,
// set a limit on the number of parents.
const MaxParent = 100

func (m MavenManifestIO) mergeParents(ctx context.Context, result *maven.Project, current maven.Parent, start int, path string, allowLocal bool, addRequirements func(maven.Project, string), prefix string) error {
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
		addRequirements(proj, mavenOrigin(prefix, current.ProjectKey.Name()))
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
