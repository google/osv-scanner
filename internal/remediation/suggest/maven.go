package suggest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/remediation/upgrade"
	"github.com/google/osv-scanner/v2/internal/resolution/manifest"
	"github.com/google/osv-scanner/v2/internal/utility/maven"
)

type MavenSuggester struct{}

// Suggest returns the ManifestPatch to update Maven dependencies to a newer
// version based on the options.
// ManifestPatch also includes the property patches to update.
func (ms *MavenSuggester) Suggest(ctx context.Context, cl resolve.Client, mf manifest.Manifest, opts Options) (manifest.Patch, error) {
	specific, ok := mf.EcosystemSpecific.(manifest.MavenManifestSpecific)
	if !ok {
		return manifest.Patch{}, errors.New("invalid MavenManifestSpecific data")
	}

	var changedDeps []manifest.DependencyPatch //nolint:prealloc
	for _, req := range append(mf.Requirements, specific.RequirementsForUpdates...) {
		if opts.UpgradeConfig.Get(req.Name) == upgrade.None {
			continue
		}

		if opts.IgnoreDev && slices.Contains(mf.Groups[manifest.MakeRequirementKey(req)], "test") {
			// Skip the update if the dependency is of development group
			// and updates on development dependencies are not desired
			continue
		}
		if strings.Contains(req.Name, "${") && strings.Contains(req.Version, "${") {
			// If there are unresolved properties, we should skip this version.
			continue
		}

		latest, err := suggestMavenVersion(ctx, cl, req, opts.UpgradeConfig.Get(req.Name))
		if err != nil {
			return manifest.Patch{}, fmt.Errorf("suggesting latest version of %s: %w", req.Version, err)
		}
		if latest.Version == req.Version {
			// No need to update
			continue
		}

		changedDeps = append(changedDeps, manifest.DependencyPatch{
			Pkg:         req.PackageKey,
			Type:        req.Type,
			OrigRequire: req.Version,
			NewRequire:  latest.Version,
		})
	}

	return manifest.Patch{
		Deps:     changedDeps,
		Manifest: &mf,
	}, nil
}

// suggestMavenVersion returns the latest version based on the given Maven requirement version.
// If there is no newer version available, req will be returned.
// For a version range requirement,
//   - the greatest version matching the constraint is assumed when deciding whether the
//     update is a major update or not.
//   - if the latest version does not satisfy the constraint, this version is returned;
//     otherwise, the original version range requirement is returned.
func suggestMavenVersion(ctx context.Context, cl resolve.Client, req resolve.RequirementVersion, level upgrade.Level) (resolve.RequirementVersion, error) {
	versions, err := cl.Versions(ctx, req.PackageKey)
	if err != nil {
		return resolve.RequirementVersion{}, fmt.Errorf("requesting versions of Maven package %s: %w", req.Name, err)
	}
	semvers := make([]*semver.Version, 0, len(versions))
	for _, ver := range versions {
		parsed, err := semver.Maven.Parse(ver.Version)
		if err != nil {
			cmdlogger.Warnf("parsing Maven version %s: %v", parsed, err)
			continue
		}
		semvers = append(semvers, parsed)
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
		if maven.CompareVersions(req.VersionKey, v, newReq) < 0 {
			// Skip versions smaller than the current requirement
			continue
		}
		if _, diff := v.Difference(current); !level.Allows(diff) {
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
