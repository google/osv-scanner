package suggester

import (
	"context"
	"fmt"
	"log"

	"deps.dev/util/resolve"
	"deps.dev/util/semver"
)

type MavenSuggester struct{}

// Suggest returns the latest version based on the given Maven requirement version.
// If there is no newer version available, req will be returned.
// For a version range requirement,
//   - the greatest version matching the constraint is assumed when deciding whether the
//     update is a major update or not.
//   - if the latest version does not satisfy the constraint, this version is returned;
//     otherwise, the original version range requirement is returned.
func (ms *MavenSuggester) Suggest(ctx context.Context, client resolve.Client, req resolve.RequirementVersion, opts SuggestOptions) (resolve.RequirementVersion, error) {
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
		// Guess the latest version statisfying the constraint is being used
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
		if _, diff := v.Difference(current); diff == semver.DiffMajor && opts.NoMajorUpdates {
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
