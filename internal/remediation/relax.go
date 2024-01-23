package remediation

import (
	"context"
	"errors"
	"slices"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/remediation/relaxer"
	"github.com/google/osv-scanner/internal/resolution"
)

//nolint:unused
var errRelaxRemediateImpossible = errors.New("cannot fix vulns by relaxing")

//nolint:unused
func tryRelaxRemediate(
	ctx context.Context,
	cl resolve.Client,
	orig *resolution.ResolutionResult,
	vulnIDs []string,
	opts RemediationOptions,
) (*resolution.ResolutionResult, error) {
	relaxer, err := relaxer.GetRelaxer(orig.Manifest.System())
	if err != nil {
		return nil, err
	}

	newRes := orig
	toRelax := reqsToRelax(newRes, vulnIDs, opts)
	for len(toRelax) > 0 {
		// Try relaxing all necessary requirements
		manif := newRes.Manifest.Clone()
		for _, idx := range toRelax {
			rv := manif.Requirements[idx]
			// If we'd need to relax a package we want to avoid changing, we cannot fix the vuln
			if slices.Contains(opts.AvoidPkgs, rv.Name) {
				return nil, errRelaxRemediateImpossible
			}
			newVer, ok := relaxer.Relax(ctx, cl, rv, opts.AllowMajor)
			if !ok {
				return nil, errRelaxRemediateImpossible
			}
			manif.Requirements[idx] = newVer
		}

		// re-resolve relaxed manifest
		newRes, err = resolution.Resolve(ctx, cl, manif)
		if err != nil {
			return nil, err
		}
		toRelax = reqsToRelax(newRes, vulnIDs, opts)
	}

	return newRes, nil
}

//nolint:unused
func reqsToRelax(res *resolution.ResolutionResult, vulnIDs []string, opts RemediationOptions) []int {
	toRelax := make(map[resolve.VersionKey]string)
	for _, v := range res.Vulns {
		// Don't do a full opts.MatchVuln() since we know we don't need to check every condition
		if !slices.Contains(vulnIDs, v.Vulnerability.ID) || (!opts.DevDeps && v.DevOnly) {
			continue
		}
		chains := v.ProblemChains
		if len(chains) == 0 {
			// Just in case something is wrong with the problem heuristic
			chains = v.NonProblemChains
		}
		// Only relax dependencies if their chain length is less than MaxDepth
		for _, ch := range chains {
			if opts.MaxDepth <= 0 || len(ch.Edges) <= opts.MaxDepth {
				vk, req := ch.DirectDependency()
				toRelax[vk] = req
			}
		}
	}

	// Find the index into the Manifest.Requirements of each that needs to be relaxed
	reqIdxs := make([]int, 0, len(toRelax))
	for vk, req := range toRelax {
		idx := slices.IndexFunc(res.Manifest.Requirements, func(rv resolve.RequirementVersion) bool {
			return rv.PackageKey == vk.PackageKey && rv.Version == req
		})
		reqIdxs = append(reqIdxs, idx)
	}

	return reqIdxs
}
