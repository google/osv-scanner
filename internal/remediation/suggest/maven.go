package suggest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/pkg/lockfile"
	"golang.org/x/exp/slices"
)

type MavenSuggester struct{}

// Suggest returns the ManifestPatch to update Maven dependencies to a newer
// version based on the options.
// ManifestPatch also includes the property patches to update.
func (ms *MavenSuggester) Suggest(ctx context.Context, client resolve.Client, mf manifest.Manifest, opts Options) (manifest.ManifestPatch, error) {
	specific, ok := mf.EcosystemSpecific.(manifest.MavenManifestSpecific)
	if !ok {
		return manifest.ManifestPatch{}, errors.New("invalid MavenManifestSpecific data")
	}

	var changedDeps []manifest.DependencyPatch
	propertyPatches := manifest.MavenPropertyPatches{}
	for _, req := range append(specific.RequirementsForUpdates, mf.Requirements...) {
		if slices.Contains(opts.NoUpdates, req.Name) {
			continue
		}
		if opts.IgnoreDev && lockfile.MavenEcosystem.IsDevGroup(mf.Groups[manifest.MakeRequirementKey(req)]) {
			// Skip the update if the dependency is of development group
			// and updates on development dependencies are not desired
			continue
		}

		latest, err := suggestMavenVersion(ctx, client, req, slices.Contains(opts.AvoidMajor, req.Name))
		if err != nil {
			return manifest.ManifestPatch{}, fmt.Errorf("suggesting latest version of %s: %w", req.Version, err)
		}
		if latest.Version == req.Version {
			// No need to update
			continue
		}

		patch := manifest.DependencyPatch{
			Pkg:        req.PackageKey,
			Type:       req.Type,
			NewRequire: latest.Version,
		}
		origReq, origin := originalRequirement(patch, specific.BaseProject)
		if origReq == "" {
			// Cannot find the original requirement indicates the requirement not in base project
			continue
		}

		dep, _, _ := resolve.MavenDepTypeToDependency(patch.Type)
		patch.Type = resolve.MavenDepType(dep, origin)

		hasPatch := func(patches []manifest.DependencyPatch, patch manifest.DependencyPatch) bool {
			for _, p := range patches {
				if p.Pkg == patch.Pkg && p.Type.Equal(patch.Type) && p.NewRequire == patch.NewRequire {
					return true
				}
			}
			return false
		}
		if hasPatch(changedDeps, patch) {
			// This update patch already exists so no need to update again.
			continue
		}

		if !origReq.ContainsProperty() {
			// The original requirement does not contain a property placeholder.
			changedDeps = append(changedDeps, patch)
			continue
		}

		patches, ok := generatePropertyPatches(string(origReq), patch.NewRequire)
		if !ok {
			// Not able to update properties to update the requirement.
			// Update the dependency directly instead.
			changedDeps = append(changedDeps, patch)
			continue
		}

		for name, value := range patches {
			propOrigin := propertyOrigin(name, specific.BaseProject)
			if _, ok := propertyPatches[propOrigin]; !ok {
				propertyPatches[propOrigin] = make(map[string]string)
			}
			// This property has been set to update to a value. If both values are the
			// same, we do nothing; otherwise, instead of updating the property, we
			// should update the dependency directly.
			if preset, ok := propertyPatches[propOrigin][name]; !ok {
				propertyPatches[propOrigin][name] = value
			} else if preset != value {
				changedDeps = append(changedDeps, patch)
			}
		}
	}

	return manifest.ManifestPatch{
		Deps:              changedDeps,
		EcosystemSpecific: propertyPatches,
	}, nil
}

// suggestMavenVersion returns the latest version based on the given Maven requirement version.
// If there is no newer version available, req will be returned.
// For a version range requirement,
//   - the greatest version matching the constraint is assumed when deciding whether the
//     update is a major update or not.
//   - if the latest version does not satisfy the constraint, this version is returned;
//     otherwise, the original version range requirement is returned.
func suggestMavenVersion(ctx context.Context, client resolve.Client, req resolve.RequirementVersion, noMajorUpdates bool) (resolve.RequirementVersion, error) {
	versions, err := client.Versions(ctx, req.PackageKey)
	if err != nil {
		return resolve.RequirementVersion{}, fmt.Errorf("requesting versions of Maven package %s: %w", req.Name, err)
	}
	semvers := make([]*semver.Version, 0, len(versions))
	for _, ver := range versions {
		v, err := semver.Maven.Parse(ver.Version)
		if err != nil {
			log.Printf("parsing Maven version %s: %v", v, err)
			continue
		}
		semvers = append(semvers, v)
	}

	constraint, err := semver.Maven.ParseConstraint(req.Version)
	if err != nil {
		return resolve.RequirementVersion{}, fmt.Errorf("parsing Maven constraint %s: %w", req.Version, err)
	}

	var current *semver.Version
	if constraint.IsSimple() {
		// Constraint is a simple version string, so can be parsed to a single version.
		current, err = semver.Maven.Parse(req.Version)
		if err != nil {
			return resolve.RequirementVersion{}, fmt.Errorf("parsing Maven version %s: %w", req.Version, err)
		}
	} else {
		// Guess the latest version satisfying the constraint is being used
		for _, v := range semvers {
			if constraint.MatchVersion(v) && current.Compare(v) < 0 {
				current = v
			}
		}
	}

	var newReq *semver.Version
	for _, v := range semvers {
		if v.Compare(newReq) < 0 {
			// Skip versions smaller than the current requirement
			continue
		}
		if _, diff := v.Difference(current); diff == semver.DiffMajor && noMajorUpdates {
			continue
		}
		newReq = v
	}
	if constraint.IsSimple() || !constraint.MatchVersion(newReq) {
		// For version range requirement, update the requirement if the
		// new requirement does not satisfy the constraint.
		req.Version = newReq.String()
	}

	return req, nil
}

// originalRequirement returns the original requirement of a requirement version and its origin.
// If the version is not found, empty strings are returned.
// TODO: DependencyPatch or other data structure?
func originalRequirement(patch manifest.DependencyPatch, project maven.Project) (maven.String, string) {
	IDs := strings.Split(patch.Pkg.Name, ":")
	if len(IDs) != 2 {
		return "", ""
	}

	dependency, origin, _ := resolve.MavenDepTypeToDependency(patch.Type)
	dependency.GroupID = maven.String(IDs[0])
	dependency.ArtifactID = maven.String(IDs[1])

	if origin == "" {

	} else if origin == manifest.OriginParent {
		if dependency.Name() == project.Parent.Name() {
			return project.Parent.Version, origin
		}
	} else if origin == manifest.OriginManagement {
		for _, d := range project.DependencyManagement.Dependencies {
			if dependency.Key() == d.Key() {
				return d.Version, manifest.OriginManagement
			}
		}
	}

	for _, d := range project.Dependencies {
		if dependency.Key() == d.Key() {
			return d.Version, ""
		}
	}
	for _, d := range project.DependencyManagement.Dependencies {
		if dependency.Key() == d.Key() {
			return d.Version, manifest.OriginManagement
		}
	}
	for _, prof := range project.Profiles {
		for _, d := range prof.Dependencies {
			if dependency.Key() == d.Key() {
				return d.Version, manifest.MavenOrigin(manifest.OriginProfile, string(prof.ID))
			}
		}
		for _, d := range prof.DependencyManagement.Dependencies {
			if dependency.Key() == d.Key() {
				return d.Version, manifest.MavenOrigin(manifest.OriginProfile, string(prof.ID), manifest.OriginManagement)
			}
		}
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		for _, d := range plugin.Dependencies {
			if dependency.Key() == d.Key() {
				return d.Version, manifest.MavenOrigin(manifest.OriginPlugin, plugin.ProjectKey.Name())
			}
		}
	}

	return "", ""
}

// propertyOrigin returns the origin of a property.
// If the property is not found, an empty string is returned.
func propertyOrigin(name string, project maven.Project) string {
	for _, prop := range project.Properties.Properties {
		if prop.Name == name {
			return ""
		}
	}
	for _, prof := range project.Profiles {
		for _, prop := range prof.Properties.Properties {
			if prop.Name == name {
				return manifest.MavenOrigin(manifest.OriginProfile, string(prof.ID))
			}
		}
	}
	return ""
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
