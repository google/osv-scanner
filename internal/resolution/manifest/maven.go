package manifest

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/pkg/lockfile"
)

type MavenManifestIO struct{}

const (
	OriginManagement = "management"
	OriginParent     = "parent"
	OriginPlugin     = "plugin"
	OriginProfile    = "profile"
)

type MavenManifestSpecific struct {
	Properties      []PropertyWithOrigin
	OriginalImports []resolve.RequirementVersion
}

type PropertyWithOrigin struct {
	maven.Property
	Origin string // Origin indicates where the property comes from
}

// TODO: fetch and merge parent data
// TODO: process dependencies (imports and dedupe)
// TODO: handle profiles (activation and intepolation)
func (m MavenManifestIO) Read(df lockfile.DepFile) (Manifest, error) {
	var project maven.Project
	if err := xml.NewDecoder(df).Decode(&project); err != nil {
		return Manifest{}, fmt.Errorf("failed to unmarshal input: %w", err)
	}

	count := len(project.Properties.Properties)
	for _, prof := range project.Profiles {
		count += len(prof.Properties.Properties)
	}
	properties := make([]PropertyWithOrigin, 0, count)
	for _, prop := range project.Properties.Properties {
		properties = append(properties, PropertyWithOrigin{Property: prop})
	}

	groups := make(map[resolve.PackageKey][]string)
	// Convert Maven dependencies to an import and add them to imports.
	// Only interpolated dependencies (free of property placehoders) are added to groups
	// to avoid duplicates.
	// For dependencies in profiles and plugins, we use origin to indicate where they are from.
	// The origin is in the format prefix@identifier[@postfix] (where @ is the separator):
	//  - prefix indicates it is from profile or plugin
	//  - identifier to locate the profile/plugin which is profile ID or plugin name
	//  - (optional) suffix indicates if this is a dependency management
	addImports := func(imports *[]resolve.RequirementVersion, deps []maven.Dependency, origin string, interpolated bool) {
		for _, dep := range deps {
			pk := resolve.PackageKey{
				System: resolve.Maven,
				Name:   mavenDepName(dep),
			}
			*imports = append(*imports, resolve.RequirementVersion{
				VersionKey: resolve.VersionKey{
					PackageKey:  pk,
					VersionType: resolve.Requirement,
					Version:     string(dep.Version),
				},
				Type: makeMavenDepType(dep, origin),
			})
			if interpolated && dep.Scope != "" {
				groups[pk] = append(groups[pk], string(dep.Scope))
			}
		}
	}

	var originalImports []resolve.RequirementVersion
	addImports(&originalImports, project.Dependencies, "", false)
	addImports(&originalImports, project.DependencyManagement.Dependencies, OriginManagement, false)
	for _, profile := range project.Profiles {
		addImports(&originalImports, profile.Dependencies, mavenOrigin(OriginProfile, string(profile.ID)), false)
		addImports(&originalImports, profile.DependencyManagement.Dependencies, mavenOrigin(OriginProfile, string(profile.ID), OriginManagement), false)
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		addImports(&originalImports, plugin.Dependencies, mavenOrigin(OriginPlugin, mavenName(plugin.ProjectKey)), false)
	}

	// Interpolate the project to resolve the properties.
	if err := project.Interpolate(); err != nil {
		return Manifest{}, fmt.Errorf("failed to interpolate project: %w", err)
	}

	var imports []resolve.RequirementVersion
	if project.Parent.GroupID != "" && project.Parent.ArtifactID != "" {
		imports = append(imports, resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   mavenName(project.Parent.ProjectKey),
				},
				// Parent version is a concrete version, but we model parent as dependency here.
				VersionType: resolve.Requirement,
				Version:     string(project.Parent.Version),
			},
			Type: makeMavenDepType(maven.Dependency{}, OriginParent),
		})
	}
	addImports(&imports, project.Dependencies, "", true)
	addImports(&imports, project.DependencyManagement.Dependencies, OriginManagement, true)
	for _, profile := range project.Profiles {
		addImports(&imports, profile.Dependencies, mavenOrigin(OriginProfile, string(profile.ID)), true)
		addImports(&imports, profile.DependencyManagement.Dependencies, mavenOrigin(OriginProfile, string(profile.ID), OriginManagement), true)
		for _, prop := range profile.Properties.Properties {
			properties = append(properties, PropertyWithOrigin{
				Property: prop,
				Origin:   mavenOrigin(OriginProfile, string(profile.ID)),
			})
		}
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		addImports(&imports, plugin.Dependencies, mavenOrigin(OriginPlugin, mavenName(plugin.ProjectKey)), true)
	}

	return Manifest{
		FilePath: df.Path(),
		Root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   mavenName(project.ProjectKey),
				},
				VersionType: resolve.Concrete,
				Version:     string(project.Version),
			},
		},
		Requirements: imports,
		Groups:       groups,
		EcosystemSpecific: MavenManifestSpecific{
			Properties:      properties,
			OriginalImports: originalImports,
		},
	}, nil
}

func mavenName(key maven.ProjectKey) string {
	return fmt.Sprintf("%s:%s", key.GroupID, key.ArtifactID)
}

func mavenDepName(dep maven.Dependency) string {
	return fmt.Sprintf("%s:%s", dep.GroupID, dep.ArtifactID)
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

func makeMavenDepType(dependency maven.Dependency, origin string) dep.Type {
	var dt dep.Type
	if dependency.Optional == "true" {
		dt.AddAttr(dep.Opt, "")
	}
	if dependency.Scope == "test" {
		dt.AddAttr(dep.Test, "")
	} else if dependency.Scope != "" && dependency.Scope != "compile" {
		dt.AddAttr(dep.Scope, string(dependency.Scope))
	}
	if dependency.Type != "" {
		dt.AddAttr(dep.MavenArtifactType, string(dependency.Type))
	}
	if dependency.Classifier != "" {
		dt.AddAttr(dep.MavenClassifier, string(dependency.Classifier))
	}
	// Only add Maven dependency origin when it is not direct dependency.
	if origin != "" {
		dt.AddAttr(dep.MavenDependencyOrigin, origin)
	}

	return dt
}

func depTypeToMavenDependency(typ dep.Type) (maven.Dependency, string, error) {
	result := maven.Dependency{}
	if _, ok := typ.GetAttr(dep.Opt); ok {
		result.Optional = "true"
	}
	if _, ok := typ.GetAttr(dep.Test); ok {
		result.Scope = "test"
	}
	if s, ok := typ.GetAttr(dep.Scope); ok {
		if result.Scope != "" {
			return maven.Dependency{}, "", errors.New("invalid Maven dep.Type")
		}
		result.Scope = maven.String(s)
	}
	if c, ok := typ.GetAttr(dep.MavenClassifier); ok {
		result.Classifier = maven.String(c)
	}
	if t, ok := typ.GetAttr(dep.MavenArtifactType); ok {
		result.Type = maven.String(t)
	}
	if o, ok := typ.GetAttr(dep.MavenDependencyOrigin); ok {
		return result, o, nil
	}

	return result, "", nil
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
		_, o, err := depTypeToMavenDependency(changedDep.Type)
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
					return fmt.Errorf("cannot convert ecosystem specific information to Maven properties")
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
				if err := updateProject(enc, "<plugin>"+rawPlugin.InnerXML+"</plugin>", OriginPlugin, mavenName(rawPlugin.ProjectKey), patches, properties); err != nil {
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
					d, _, err := depTypeToMavenDependency(patch.Type)
					if err != nil {
						return fmt.Errorf("depTypeToMavenDependency: %w", err)
					}
					// A Maven dependency key consists of Type and Classifier together with GroupID and ArtifactID.
					if patch.Pkg.Name == mavenDepName(rawDep.Dependency) && d.Type == rawDep.Type && d.Classifier == rawDep.Classifier {
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
