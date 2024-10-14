package manifest

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	internalxml "github.com/google/osv-scanner/internal/thirdparty/xml"
	mavenutil "github.com/google/osv-scanner/internal/utility/maven"
	"github.com/google/osv-scanner/pkg/lockfile"
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

type MavenReadWriter struct {
	*datasource.MavenRegistryAPIClient
}

func (MavenReadWriter) System() resolve.System { return resolve.Maven }

func NewMavenReadWriter(registry string) (MavenReadWriter, error) {
	client, err := datasource.NewMavenRegistryAPIClient(registry)
	if err != nil {
		return MavenReadWriter{}, err
	}

	return MavenReadWriter{MavenRegistryAPIClient: client}, nil
}

type MavenManifestSpecific struct {
	Parent                 maven.Parent
	Properties             []PropertyWithOrigin         // Properties from the base project
	OriginalRequirements   []DependencyWithOrigin       // Dependencies from the base project
	RequirementsForUpdates []resolve.RequirementVersion // Requirements that we only need for updates
	Repositories           []maven.Repository
}

type PropertyWithOrigin struct {
	maven.Property
	Origin string // Origin indicates where the property comes from
}

type DependencyWithOrigin struct {
	maven.Dependency
	Origin string // Origin indicates where the dependency comes from
}

func (m MavenReadWriter) Read(df lockfile.DepFile) (Manifest, error) {
	ctx := context.Background()

	var project maven.Project
	if err := datasource.NewMavenDecoder(df).Decode(&project); err != nil {
		return Manifest{}, fmt.Errorf("failed to unmarshal project: %w", err)
	}
	properties := buildPropertiesWithOrigins(project, "")
	origRequirements := buildOriginalRequirements(project, "")

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
			Type: resolve.MavenDepType(maven.Dependency{Type: "pom"}, mavenutil.OriginParent),
		})
	}

	// Empty JDK and ActivationOS indicates merging the default profiles.
	if err := project.MergeProfiles("", maven.ActivationOS{}); err != nil {
		return Manifest{}, fmt.Errorf("failed to merge profiles: %w", err)
	}
	for _, repo := range project.Repositories {
		if err := m.MavenRegistryAPIClient.AddRegistry(string(repo.URL)); err != nil {
			return Manifest{}, fmt.Errorf("failed to add registry %s: %w", repo.URL, err)
		}
	}

	// Merging parents data by parsing local parent pom.xml or fetching from upstream.
	if err := mavenutil.MergeParents(ctx, m.MavenRegistryAPIClient, &project, project.Parent, 1, df.Path(), true); err != nil {
		return Manifest{}, fmt.Errorf("failed to merge parents: %w", err)
	}

	// For dependency management imports, the dependencies that imports
	// dependencies from other projects will be replaced by the imported
	// dependencies, so add them to requirements first.
	for _, dep := range project.DependencyManagement.Dependencies {
		if dep.Scope == "import" && dep.Type == "pom" {
			reqsForUpdates = append(reqsForUpdates, makeRequirementVersion(dep, mavenutil.OriginManagement))
		}
	}

	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		return mavenutil.GetDependencyManagement(ctx, m.MavenRegistryAPIClient, groupID, artifactID, version)
	})

	groups := make(map[RequirementKey][]string)
	requirements := addRequirements([]resolve.RequirementVersion{}, groups, project.Dependencies, "")
	requirements = addRequirements(requirements, groups, project.DependencyManagement.Dependencies, mavenutil.OriginManagement)

	// Requirements may not appear in the dependency graph but needs to be updated.
	for _, profile := range project.Profiles {
		reqsForUpdates = addRequirements(reqsForUpdates, groups, profile.Dependencies, "")
		reqsForUpdates = addRequirements(reqsForUpdates, groups, profile.DependencyManagement.Dependencies, mavenutil.OriginManagement)
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		reqsForUpdates = addRequirements(reqsForUpdates, groups, plugin.Dependencies, "")
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
			Parent:                 project.Parent,
			Properties:             properties,
			OriginalRequirements:   origRequirements,
			RequirementsForUpdates: reqsForUpdates,
			Repositories:           project.Repositories,
		},
	}, nil
}

func addRequirements(reqs []resolve.RequirementVersion, groups map[RequirementKey][]string, deps []maven.Dependency, origin string) []resolve.RequirementVersion {
	for _, d := range deps {
		reqVer := makeRequirementVersion(d, origin)
		reqs = append(reqs, reqVer)
		if d.Scope != "" {
			reqKey := mavenRequirementKey(reqVer)
			groups[reqKey] = append(groups[reqKey], string(d.Scope))
		}
	}

	return reqs
}

func buildPropertiesWithOrigins(project maven.Project, originPrefix string) []PropertyWithOrigin {
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
				Origin:   mavenOrigin(originPrefix, mavenutil.OriginProfile, string(profile.ID)),
			})
		}
	}

	return properties
}

func buildOriginalRequirements(project maven.Project, originPrefix string) []DependencyWithOrigin {
	var dependencies []DependencyWithOrigin //nolint:prealloc
	if project.Parent.GroupID != "" && project.Parent.ArtifactID != "" {
		dependencies = append(dependencies, DependencyWithOrigin{
			Dependency: maven.Dependency{
				GroupID:    project.Parent.GroupID,
				ArtifactID: project.Parent.ArtifactID,
				Version:    project.Parent.Version,
				Type:       "pom",
			},
			Origin: mavenOrigin(originPrefix, mavenutil.OriginParent),
		})
	}
	for _, d := range project.Dependencies {
		dependencies = append(dependencies, DependencyWithOrigin{Dependency: d, Origin: originPrefix})
	}
	for _, d := range project.DependencyManagement.Dependencies {
		dependencies = append(dependencies, DependencyWithOrigin{
			Dependency: d,
			Origin:     mavenOrigin(originPrefix, mavenutil.OriginManagement),
		})
	}
	for _, prof := range project.Profiles {
		for _, d := range prof.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(originPrefix, mavenutil.OriginProfile, string(prof.ID)),
			})
		}
		for _, d := range prof.DependencyManagement.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(originPrefix, mavenutil.OriginProfile, string(prof.ID), mavenutil.OriginManagement),
			})
		}
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		for _, d := range plugin.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(originPrefix, mavenutil.OriginPlugin, plugin.ProjectKey.Name()),
			})
		}
	}

	return dependencies
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

func (MavenReadWriter) Write(df lockfile.DepFile, w io.Writer, patch Patch) error {
	specific, ok := patch.Manifest.EcosystemSpecific.(MavenManifestSpecific)
	if !ok {
		return errors.New("invalid MavenManifestSpecific data")
	}

	// Walk through local parent pom.xml for original dependencies and properties.
	// TODO: investigate if this can be done when merging parents in manifest reading
	currentPath := df.Path()
	parent := specific.Parent
	visited := make(map[maven.ProjectKey]bool, mavenutil.MaxParent)
	for range mavenutil.MaxParent {
		if parent.GroupID == "" || parent.ArtifactID == "" || parent.Version == "" {
			break
		}
		if visited[parent.ProjectKey] {
			// A cycle of parents is detected
			return errors.New("a cycle of parents is detected")
		}
		visited[parent.ProjectKey] = true

		currentPath = mavenutil.ParentPOMPath(currentPath, string(parent.RelativePath))
		if currentPath == "" {
			// No more local parent pom.xml exists.
			break
		}

		f, err := os.Open(currentPath)
		if err != nil {
			return fmt.Errorf("failed to open parent file %s: %w", currentPath, err)
		}

		var proj maven.Project
		err = datasource.NewMavenDecoder(f).Decode(&proj)
		f.Close()
		if err != nil {
			return fmt.Errorf("failed to unmarshal project: %w", err)
		}
		if mavenutil.ProjectKey(proj) != parent.ProjectKey || proj.Packaging != "pom" {
			// This is not the project that we are looking for, we should fetch from upstream
			// that we don't have write access so we give up here.
			break
		}

		origin := mavenOrigin(mavenutil.OriginParent, currentPath)
		specific.OriginalRequirements = append(specific.OriginalRequirements, buildOriginalRequirements(proj, origin)...)
		specific.Properties = append(specific.Properties, buildPropertiesWithOrigins(proj, origin)...)
		parent = proj.Parent
	}

	allPatches, err := buildPatches(patch.Deps, specific)
	if err != nil {
		return err
	}

	for path, patches := range allPatches {
		if path == "" {
			// Base pom.xml is going to be written later.
			continue
		}
		// TODO: investigate how to test parent manifests are updated.
		depFile, err := lockfile.OpenLocalDepFile(path)
		if err != nil {
			return err
		}
		in := new(bytes.Buffer)
		if _, err := in.ReadFrom(depFile); err != nil {
			return fmt.Errorf("failed to read from DepFile: %w", err)
		}
		depFile.Close() // Make sure the file is closed before we start writing to it.

		out := new(bytes.Buffer)
		if err := write(in.String(), out, patches); err != nil {
			return err
		}
		//nolint:gosec
		if err := os.WriteFile(path, out.Bytes(), 0644); err != nil {
			return err
		}
	}

	in := new(bytes.Buffer)
	if _, err := in.ReadFrom(df); err != nil {
		return fmt.Errorf("failed to read from DepFile: %w", err)
	}

	return write(in.String(), w, allPatches[""])
}

type MavenPatches struct {
	DependencyPatches MavenDependencyPatches
	PropertyPatches   MavenPropertyPatches
}

type MavenPatch struct {
	maven.DependencyKey
	NewRequire string
}

// MavenDependencyPatches represent the dependencies to be updated, which
// is a map of dependency patches of each origin.
type MavenDependencyPatches map[string]map[MavenPatch]bool //  origin -> patch -> whether from this project

// addPatch adds a patch to the patches map indexed by origin.
// exist indicates whether this patch comes from the project.
func (m MavenDependencyPatches) addPatch(changedDep DependencyPatch, exist bool) error {
	d, o, err := resolve.MavenDepTypeToDependency(changedDep.Type)
	if err != nil {
		return fmt.Errorf("MavenDepTypeToDependency: %w", err)
	}

	// If this dependency did not already exist in the project, we want to add it to the dependencyManagement section
	if !exist {
		o = mavenutil.OriginManagement
	}

	substrings := strings.Split(changedDep.Pkg.Name, ":")
	if len(substrings) != 2 {
		return fmt.Errorf("invalid Maven name: %s", changedDep.Pkg.Name)
	}
	d.GroupID = maven.String(substrings[0])
	d.ArtifactID = maven.String(substrings[1])

	if _, ok := m[o]; !ok {
		m[o] = make(map[MavenPatch]bool)
	}
	m[o][MavenPatch{
		DependencyKey: d.Key(),
		NewRequire:    changedDep.NewRequire,
	}] = exist

	return nil
}

// MavenPropertyPatches represent the properties to be updated, which
// is a map of properties of each origin.
type MavenPropertyPatches map[string]map[string]string // origin -> tag -> value

// parentPathFromOrigin returns the parent path embedded in origin,
// as well as the remaining origin string.
func parentPathFromOrigin(origin string) (string, string) {
	tokens := strings.Split(origin, "@")
	if len(tokens) <= 1 {
		return "", origin
	}
	if tokens[0] != mavenutil.OriginParent {
		return "", origin
	}

	return tokens[1], strings.Join(tokens[2:], "")
}

// buildPatches returns dependency patches ready for updates.
func buildPatches(patches []DependencyPatch, specific MavenManifestSpecific) (map[string]MavenPatches, error) {
	result := make(map[string]MavenPatches)
	for _, patch := range patches {
		var path string
		origDep := originalDependency(patch, specific.OriginalRequirements)
		path, origDep.Origin = parentPathFromOrigin(origDep.Origin)
		if _, ok := result[path]; !ok {
			result[path] = MavenPatches{
				DependencyPatches: MavenDependencyPatches{},
				PropertyPatches:   MavenPropertyPatches{},
			}
		}
		if origDep.Name() == ":" {
			// An empty name indicates the dependency is not found, so the original dependency is not in the base project.
			// If the patch is from suggest (origRequire is set), we ignore this patch.
			// If the patch is from override (origRequire is empty), we add this patch.
			if patch.OrigRequire == "" {
				if err := result[path].DependencyPatches.addPatch(patch, false); err != nil {
					return nil, err
				}
			}

			continue
		}

		patch.Type = resolve.MavenDepType(origDep.Dependency, origDep.Origin)
		if !origDep.Version.ContainsProperty() {
			// The original requirement does not contain a property placeholder.
			if err := result[path].DependencyPatches.addPatch(patch, true); err != nil {
				return nil, err
			}

			continue
		}

		properties, ok := generatePropertyPatches(string(origDep.Version), patch.NewRequire)
		if !ok {
			// Not able to update properties to update the requirement.
			// Update the dependency directly instead.
			if err := result[path].DependencyPatches.addPatch(patch, true); err != nil {
				return nil, err
			}

			continue
		}

		depOrigin := origDep.Origin
		if strings.HasPrefix(depOrigin, mavenutil.OriginProfile) {
			// Dependency management is not indicated in property origin.
			depOrigin, _ = strings.CutSuffix(depOrigin, "@"+mavenutil.OriginManagement)
		} else {
			// Properties are defined either universally or in a profile. For property
			// origin not starting with 'profile', this is an universal property.
			depOrigin = ""
		}

		for name, value := range properties {
			// A dependency in a profile may contain properties from this profile or
			// properties universally defined. We need to figure out the origin of these
			// properties. If a property is defined both universally and in the profile,
			// we use the profile's origin.
			propertyOrigin := ""
			for _, p := range specific.Properties {
				if p.Name == name && p.Origin != "" && p.Origin == depOrigin {
					propertyOrigin = depOrigin
				}
			}
			if _, ok := result[path].PropertyPatches[propertyOrigin]; !ok {
				result[path].PropertyPatches[propertyOrigin] = make(map[string]string)
			}
			// This property has been set to update to a value. If both values are the
			// same, we do nothing; otherwise, instead of updating the property, we
			// should update the dependency directly.
			if preset, ok := result[path].PropertyPatches[propertyOrigin][name]; !ok {
				result[path].PropertyPatches[propertyOrigin][name] = value
			} else if preset != value {
				if err := result[path].DependencyPatches.addPatch(patch, true); err != nil {
					return nil, err
				}
			}
		}
	}

	return result, nil
}

// originalDependency returns the original dependency of a dependency patch.
// If the dependency is not found in any local pom.xml, an empty dependency is returned.
func originalDependency(patch DependencyPatch, origDeps []DependencyWithOrigin) DependencyWithOrigin {
	IDs := strings.Split(patch.Pkg.Name, ":")
	if len(IDs) != 2 {
		return DependencyWithOrigin{}
	}

	dependency, _, _ := resolve.MavenDepTypeToDependency(patch.Type)
	dependency.GroupID = maven.String(IDs[0])
	dependency.ArtifactID = maven.String(IDs[1])

	for _, d := range origDeps {
		if d.Key() == dependency.Key() && d.Version != "" {
			// If the version is empty, keep looking until we find some non-empty requirement.
			return d
		}
	}

	return DependencyWithOrigin{}
}

// generatePropertyPatches returns whether we are able to assign values to
// placeholder keys to convert s1 to s2, as well as the generated patches.
// s1 contains property placeholders like '${name}' and s2 is the target string.
func generatePropertyPatches(s1, s2 string) (map[string]string, bool) {
	patches := make(map[string]string)
	ok := generatePropertyPatchesAux(s1, s2, patches)

	return patches, ok
}

// generatePropertyPatchesAux generates property patches and store them in patches.
// TODO: property may refer to another property ${${name}.version}
func generatePropertyPatchesAux(s1, s2 string, patches map[string]string) bool {
	start := strings.Index(s1, "${")
	if s1[:start] != s2[:start] {
		// Cannot update property to match the prefix
		return false
	}
	end := strings.Index(s1, "}")
	next := strings.Index(s1[end+1:], "${")
	if next < 0 {
		// There are no more placeholders.
		remainder := s1[end+1:]
		if remainder == s2[len(s2)-len(remainder):] {
			patches[s1[start+2:end]] = s2[start : len(s2)-len(remainder)]
			return true
		}
	} else if match := strings.Index(s2[start:], s1[end+1:end+1+next]); match > 0 {
		// Try to match the substring between two property placeholders.
		patches[s1[start+2:end]] = s2[start : start+match]
		return generatePropertyPatchesAux(s1[end+1:], s2[start+match:], patches)
	}

	return false
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

// Only for writing dependencies that are not from the base project.
type dependencyManagement struct {
	Dependencies []dependency `xml:"dependencies>dependency,omitempty"`
}

type dependency struct {
	GroupID    string `xml:"groupId,omitempty"`
	ArtifactID string `xml:"artifactId,omitempty"`
	Version    string `xml:"version,omitempty"`
	Type       string `xml:"type,omitempty"`
	Classifier string `xml:"classifier,omitempty"`
}

func makeDependency(patch MavenPatch) dependency {
	d := dependency{
		GroupID:    string(patch.GroupID),
		ArtifactID: string(patch.ArtifactID),
		Version:    patch.NewRequire,
		Classifier: string(patch.Classifier),
	}
	if patch.Type != "" && patch.Type != "jar" {
		d.Type = string(patch.Type)
	}

	return d
}

func compareDependency(d1, d2 dependency) int {
	if i := cmp.Compare(d1.GroupID, d2.GroupID); i != 0 {
		return i
	}
	if i := cmp.Compare(d1.ArtifactID, d2.ArtifactID); i != 0 {
		return i
	}
	if i := cmp.Compare(d1.Type, d2.Type); i != 0 {
		return i
	}
	if i := cmp.Compare(d1.Classifier, d2.Classifier); i != 0 {
		return i
	}

	return cmp.Compare(d1.Version, d2.Version)
}

func write(raw string, w io.Writer, patches MavenPatches) error {
	dec := internalxml.NewDecoder(bytes.NewReader([]byte(raw)))
	enc := internalxml.NewEncoder(w)

	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("getting token: %w", err)
		}

		if tt, ok := token.(internalxml.StartElement); ok {
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
				projectStart := projectStartElement(raw)
				if projectStart == "" {
					return errors.New("unable to get start element of project")
				}
				if _, err := w.Write([]byte(projectStart)); err != nil {
					return fmt.Errorf("writing start element of project: %w", err)
				}

				// Then we update the project by passing the innerXML and name spaces are not passed.
				updated := make(map[string]bool) // origin -> updated
				if err := writeProject(w, enc, rawProj.InnerXML, "", "", patches.DependencyPatches, patches.PropertyPatches, updated); err != nil {
					return fmt.Errorf("updating project: %w", err)
				}

				// Check whether dependency management is updated, if not, add a new section of dependency management.
				if dmPatches := patches.DependencyPatches[mavenutil.OriginManagement]; len(dmPatches) > 0 && !updated[mavenutil.OriginManagement] {
					enc.Indent("  ", "  ")
					var dm dependencyManagement
					for p := range dmPatches {
						dm.Dependencies = append(dm.Dependencies, makeDependency(p))
					}
					// Sort dependency management for consistency in testing.
					slices.SortFunc(dm.Dependencies, compareDependency)
					if err := enc.Encode(dm); err != nil {
						return err
					}
					if _, err := w.Write([]byte("\n\n")); err != nil {
						return err
					}
					enc.Indent("", "")
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

func writeProject(w io.Writer, enc *internalxml.Encoder, raw, prefix, id string, patches MavenDependencyPatches, properties MavenPropertyPatches, updated map[string]bool) error {
	dec := internalxml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if tt, ok := token.(internalxml.StartElement); ok {
			switch tt.Name.Local {
			case "parent":
				updated["parent"] = true
				type RawParent struct {
					maven.ProjectKey
					InnerXML string `xml:",innerxml"`
				}
				var rawParent RawParent
				if err := dec.DecodeElement(&rawParent, &tt); err != nil {
					return err
				}
				req := string(rawParent.Version)
				if parentPatches, ok := patches["parent"]; ok {
					// There should only be one parent patch
					if len(parentPatches) > 1 {
						return fmt.Errorf("multiple parent patches: %v", parentPatches)
					}
					for k := range parentPatches {
						req = k.NewRequire
					}
				}
				if err := writeString(enc, "<parent>"+rawParent.InnerXML+"</parent>", map[string]string{"version": req}); err != nil {
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
				if err := writeString(enc, "<properties>"+rawProperties.InnerXML+"</properties>", properties[mavenOrigin(prefix, id)]); err != nil {
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
				if err := writeProject(w, enc, "<profile>"+rawProfile.InnerXML+"</profile>", mavenutil.OriginProfile, string(rawProfile.ID), patches, properties, updated); err != nil {
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
				if err := writeProject(w, enc, "<plugin>"+rawPlugin.InnerXML+"</plugin>", mavenutil.OriginPlugin, rawPlugin.ProjectKey.Name(), patches, properties, updated); err != nil {
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
				o := mavenOrigin(prefix, id, mavenutil.OriginManagement)
				updated[o] = true
				dmPatches := patches[o]
				if err := writeDependency(w, enc, "<dependencyManagement>"+rawDepMgmt.InnerXML+"</dependencyManagement>", dmPatches); err != nil {
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
				o := mavenOrigin(prefix, id)
				updated[o] = true
				depPatches := patches[o]
				if err := writeDependency(w, enc, "<dependencies>"+rawDeps.InnerXML+"</dependencies>", depPatches); err != nil {
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

func writeDependency(w io.Writer, enc *internalxml.Encoder, raw string, patches map[MavenPatch]bool) error {
	dec := internalxml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if tt, ok := token.(internalxml.StartElement); ok {
			if tt.Name.Local == "dependencies" {
				// We still need to write the start element <dependencies>
				if err := enc.EncodeToken(token); err != nil {
					return err
				}
				if err := enc.Flush(); err != nil {
					return err
				}

				// Write patches that are not in the base project.
				var deps []dependency
				for p, ok := range patches {
					if !ok {
						deps = append(deps, makeDependency(p))
					}
				}
				if len(deps) == 0 {
					// No dependencies to add
					continue
				}
				// Sort dependencies for consistency in testing.
				slices.SortFunc(deps, compareDependency)

				enc.Indent("      ", "  ")
				// Write a new line to keep the format.
				if _, err := w.Write([]byte("\n")); err != nil {
					return err
				}
				for _, d := range deps {
					if err := enc.Encode(d); err != nil {
						return err
					}
				}
				enc.Indent("", "")

				continue
			}
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
				for patch := range patches {
					// A Maven dependency key consists of Type and Classifier together with GroupID and ArtifactID.
					if patch.DependencyKey == rawDep.Key() {
						req = patch.NewRequire
					}
				}
				// xml.EncodeElement writes all empty elements and may not follow the existing format.
				// Passing the innerXML can help to keep the original format.
				if err := writeString(enc, "<dependency>"+rawDep.InnerXML+"</dependency>", map[string]string{"version": req}); err != nil {
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

// writeString writes XML string specified by raw with replacements specified in values.
func writeString(enc *internalxml.Encoder, raw string, values map[string]string) error {
	dec := internalxml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if tt, ok := token.(internalxml.StartElement); ok {
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
