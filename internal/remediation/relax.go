package remediation

import (
	"context"
	"errors"
	"slices"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/remediation/relaxer"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/client"
)

// ComputeRelaxPatches attempts to resolve each vulnerability found in result independently, returning the list of unique possible patches
func ComputeRelaxPatches(ctx context.Context, cl client.ResolutionClient, result *resolution.ResolutionResult, opts RemediationOptions) ([]resolution.ResolutionDiff, error) {
	// Filter the original result just in case it hasn't been already
	result.FilterVulns(opts.MatchVuln)

	// Do the resolutions concurrently
	type relaxResult struct {
		vulnIDs []string
		result  *resolution.ResolutionResult
		err     error
	}
	ch := make(chan relaxResult)
	doRelax := func(vulnIDs []string) {
		res, err := tryRelaxRemediate(ctx, cl, result, vulnIDs, opts)
		if err == nil {
			res.FilterVulns(opts.MatchVuln)
		}
		ch <- relaxResult{
			vulnIDs: vulnIDs,
			result:  res,
			err:     err,
		}
	}

	toProcess := 0
	for _, vuln := range result.Vulns {
		// TODO: limit the number of goroutines
		go doRelax([]string{vuln.Vulnerability.ID})
		toProcess++
	}

	var allResults []resolution.ResolutionDiff
	for toProcess > 0 {
		res := <-ch
		toProcess--
		if errors.Is(res.err, errRelaxRemediateImpossible) { // failed because it cannot be resolved - do not add it to list
			continue
		}
		if res.err != nil { // failed for some other reason - abort
			// TODO: stop goroutines
			return nil, res.err
		}
		diff := result.CalculateDiff(res.result)
		allResults = append(allResults, diff)

		// If this patch adds a new vuln, see if we can fix it also
		// TODO: If there's more than 1 added vuln, this can possibly cause every permutation of those vulns to be computed
		for _, added := range diff.AddedVulns {
			go doRelax(append(slices.Clone(res.vulnIDs), added.Vulnerability.ID))
			toProcess++
		}
	}

	// Sort and remove duplicate patches
	slices.SortFunc(allResults, func(a, b resolution.ResolutionDiff) int { return a.Compare(b) })
	allResults = slices.CompactFunc(allResults, func(a, b resolution.ResolutionDiff) bool { return a.Compare(b) == 0 })

	return allResults, nil
}

var errRelaxRemediateImpossible = errors.New("cannot fix vulns by relaxing")

func tryRelaxRemediate(
	ctx context.Context,
	cl client.ResolutionClient,
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

func reqsToRelax(res *resolution.ResolutionResult, vulnIDs []string, opts RemediationOptions) []int {
	toRelax := make(map[resolve.VersionKey]string)
	for _, v := range res.Vulns {
		// Don't do a full opts.MatchVuln() since we know we don't need to check every condition
		if !slices.Contains(vulnIDs, v.Vulnerability.ID) || (!opts.DevDeps && v.DevOnly) {
			continue
		}
		// Only relax dependencies if their chain length is less than MaxDepth
		for _, ch := range v.ProblemChains {
			if opts.MaxDepth <= 0 || len(ch.Edges) <= opts.MaxDepth {
				vk, req := ch.Direct()
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
