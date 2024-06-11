package remediation

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/semver"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/resolution/util"
	"github.com/google/osv-scanner/internal/utility/vulns"
)

// TODO: need to make a ManifestPatch with ecosystem-specific fields
type OverridePatch struct {
	resolve.PackageKey
	OrigVersion string
	NewVersion  string
}

func (p OverridePatch) String() string {
	return fmt.Sprintf("%s@%s -> %s", p.Name, p.OrigVersion, p.NewVersion)
}

type OverrideResultPatch struct {
	Patches       []OverridePatch
	FixedIDs      []string
	IntroducedIDs []string
}

type OverrideResult struct {
	Patches      []OverrideResultPatch
	UnfixableIDs [][]string
}

func (r OverrideResult) String() string {
	s := &strings.Builder{}
	fmt.Fprintln(s, "PATCHES:")
	for _, p := range r.Patches {
		fmt.Fprintln(s, p)
	}

	fmt.Fprintln(s, "UNFIXABLE:")
	for _, unf := range r.UnfixableIDs {
		fmt.Fprintln(s, unf)
	}

	return s.String()
}

func ComputeOverridePatches(ctx context.Context, cl client.ResolutionClient, result *resolution.ResolutionResult, opts RemediationOptions) (OverrideResult, error) {
	// TODO: this is very similar to ComputeRelaxPatches - can the common parts be factored out?
	// Filter the original result just in case it hasn't been already
	result.FilterVulns(opts.MatchVuln)

	// Do the resolutions concurrently
	type overrideResult struct {
		vulnIDs []string
		result  *resolution.ResolutionResult
		patches []OverridePatch
		err     error
	}
	ch := make(chan overrideResult)
	doOverride := func(vulnIDs []string) {
		res, patches, err := overridePatchVulns(ctx, cl, result, vulnIDs, opts)
		if err == nil {
			res.FilterVulns(opts.MatchVuln)
		}
		ch <- overrideResult{
			vulnIDs: vulnIDs,
			result:  res,
			patches: patches,
			err:     err,
		}
	}

	toProcess := 0
	for _, v := range result.Vulns {
		// TODO: limit the number of goroutines
		go doOverride([]string{v.Vulnerability.ID})
		toProcess++
	}

	var finalResult OverrideResult
	for toProcess > 0 {
		res := <-ch
		toProcess--
		if errors.Is(res.err, errOverrideImpossible) {
			finalResult.UnfixableIDs = append(finalResult.UnfixableIDs, res.vulnIDs)
			continue
		}

		if res.err != nil {
			// TODO: stop goroutines
			return OverrideResult{}, res.err
		}

		// TODO: just use ResolutionDiff directly
		changes := result.CalculateDiff(res.result)
		patch := OverrideResultPatch{
			Patches:       res.patches,
			FixedIDs:      make([]string, len(changes.RemovedVulns)),
			IntroducedIDs: make([]string, len(changes.AddedVulns)),
		}

		for i, v := range changes.RemovedVulns {
			patch.FixedIDs[i] = v.Vulnerability.ID
		}

		var newlyAdded []string

		for i, v := range changes.AddedVulns {
			id := v.Vulnerability.ID
			patch.IntroducedIDs[i] = id
			if !slices.Contains(res.vulnIDs, id) {
				newlyAdded = append(newlyAdded, id)
			}
		}
		finalResult.Patches = append(finalResult.Patches, patch)

		if len(newlyAdded) > 0 {
			go doOverride(append(res.vulnIDs, newlyAdded...)) // No need to clone res.vulnIDs here
			toProcess++
		}
	}

	for _, p := range finalResult.Patches {
		slices.Sort(p.FixedIDs)
		slices.Sort(p.IntroducedIDs)
	}
	cmpFn := func(a, b OverrideResultPatch) int {
		// 1. (fixed - introduced) / (changes) [desc]
		aRatio := (len(a.FixedIDs) - len(a.IntroducedIDs)) * (len(b.Patches))
		bRatio := (len(b.FixedIDs) - len(b.IntroducedIDs)) * (len(a.Patches))
		if c := cmp.Compare(aRatio, bRatio); c != 0 {
			return -c
		}

		// 2. number of fixed vulns [desc]
		if c := cmp.Compare(len(a.FixedIDs), len(b.FixedIDs)); c != 0 {
			return -c
		}

		// 3. number of changed deps [asc]
		if c := cmp.Compare(len(a.Patches), len(b.Patches)); c != 0 {
			return c
		}

		// 4. changed names [asc]
		for i, aDep := range a.Patches {
			bDep := b.Patches[i]
			if c := aDep.PackageKey.Compare(bDep.PackageKey); c != 0 {
				return c
			}
		}

		// 5. dependency bump amount [asc]
		for i, aDep := range a.Patches {
			bDep := b.Patches[i]
			sv := aDep.PackageKey.Semver()
			if c := sv.Compare(aDep.NewVersion, bDep.NewVersion); c != 0 {
				return c
			}
		}

		return 0
	}

	slices.SortFunc(finalResult.Patches, cmpFn)
	finalResult.Patches = slices.CompactFunc(finalResult.Patches, func(a, b OverrideResultPatch) bool { return cmpFn(a, b) == 0 })

	for i := range finalResult.UnfixableIDs {
		slices.Sort(finalResult.UnfixableIDs[i])
	}
	slices.SortFunc(finalResult.UnfixableIDs, slices.Compare)
	finalResult.UnfixableIDs = slices.CompactFunc(finalResult.UnfixableIDs, func(b, a []string) bool { return slices.Compare(a, b) == 0 })

	return finalResult, nil
}

var errOverrideImpossible = errors.New("cannot fix vulns by overrides")

func overridePatchVulns(ctx context.Context, cl client.ResolutionClient, result *resolution.ResolutionResult, vulnIDs []string, opts RemediationOptions) (*resolution.ResolutionResult, []OverridePatch, error) {
	// Try to fix as many vulns in vulnIDs as possible.
	// returns errOverrideImpossible if there are no patches that can be made to fix any of the vulnIDs
	var effectivePatches []OverridePatch
	for {
		// Find the relevant vulns affecting each version key.
		vkVulns := make(map[resolve.VersionKey][]*resolution.ResolutionVuln)
		for i, v := range result.Vulns {
			if !slices.Contains(vulnIDs, v.Vulnerability.ID) {
				continue
			}
			seenVks := make(map[resolve.VersionKey]struct{})
			for _, c := range v.ProblemChains {
				vk, _ := c.End()
				if _, seen := seenVks[vk]; !seen {
					vkVulns[vk] = append(vkVulns[vk], &result.Vulns[i])
					seenVks[vk] = struct{}{}
				}
			}
			for _, c := range v.NonProblemChains {
				vk, _ := c.End()
				if _, seen := seenVks[vk]; !seen {
					vkVulns[vk] = append(vkVulns[vk], &result.Vulns[i])
					seenVks[vk] = struct{}{}
				}
			}
		}

		if len(vkVulns) == 0 {
			// All vulns have been fixed.
			break
		}

		newPatches := make([]OverridePatch, 0, len(vkVulns))

		for vk, vulnerabilities := range vkVulns {
			// Consider vulns affecting packages we don't want to change unfixable
			if slices.Contains(opts.AvoidPkgs, vk.Name) {
				continue
			}

			sys := vk.Semver()
			// Get & sort all the valid versions of this package
			// TODO: (Maven) skip unlisted versions and versions on other registries
			versions, err := cl.Versions(ctx, vk.PackageKey)
			if err != nil {
				return nil, nil, err
			}
			cmpFunc := func(a, b resolve.Version) int { return sys.Compare(a.Version, b.Version) }
			slices.SortFunc(versions, cmpFunc)
			startIdx, vkFound := slices.BinarySearchFunc(versions, resolve.Version{VersionKey: vk}, cmpFunc)
			if vkFound {
				startIdx++
			}

			bestVK := vk
			bestCount := len(vulnerabilities) // remaining vulns

			// Find the minimal greater version that fixes as many vulnerabilities as possible.
			for _, ver := range versions[startIdx:] {
				if !opts.AllowMajor {
					if _, diff, _ := sys.Difference(vk.Version, ver.Version); diff == semver.DiffMajor {
						break
					}
				}

				count := 0 // remaining vulns
				for _, rv := range vulnerabilities {
					if vulns.IsAffected(rv.Vulnerability, util.VKToPackageDetails(ver.VersionKey)) {
						count += 1
					}
				}

				if count < bestCount {
					bestCount = count
					bestVK = ver.VersionKey

					if bestCount == 0 { // stop if there are 0 vulns remaining
						break
					}
				}
			}
			if bestCount < len(vulnerabilities) {
				newPatches = append(newPatches, OverridePatch{
					PackageKey:  vk.PackageKey,
					OrigVersion: vk.Version,
					NewVersion:  bestVK.Version,
				})
			}
		}

		if len(newPatches) == 0 {
			break
		}

		// Patch and re-resolve manifest
		newManif, err := patchManifest(newPatches, result.Manifest)
		if err != nil {
			return nil, nil, err
		}

		result, err = resolution.Resolve(ctx, cl, newManif)
		if err != nil {
			return nil, nil, err
		}

		result.FilterVulns(opts.MatchVuln)

		// If the patch applies to a package that was already patched before, update the effective patch.
		for _, p := range newPatches {
			idx := slices.IndexFunc(effectivePatches, func(op OverridePatch) bool { return op.PackageKey == p.PackageKey && op.NewVersion == p.OrigVersion })
			if idx == -1 {
				effectivePatches = append(effectivePatches, p)
			} else {
				effectivePatches[idx].NewVersion = p.NewVersion
			}
		}
	}

	if len(effectivePatches) == 0 {
		return nil, nil, errOverrideImpossible
	}

	return result, effectivePatches, nil
}

func patchManifest(patches []OverridePatch, m manifest.Manifest) (manifest.Manifest, error) {
	if m.System() != resolve.Maven {
		return manifest.Manifest{}, errors.New("unsupported ecosystem")
	}

	// TODO: may need special handling for the artifact's type and classifier

	patched := m.Clone()

	for _, p := range patches {
		found := false
		i := 0
		for _, r := range patched.Requirements {
			if r.PackageKey != p.PackageKey {
				patched.Requirements[i] = r
				i++

				continue
			}
			if origin, hasOrigin := r.Type.GetAttr(dep.MavenDependencyOrigin); !hasOrigin || origin == "management" {
				found = true
				r.Version = p.NewVersion
				patched.Requirements[i] = r
				i++
			}
		}
		patched.Requirements = patched.Requirements[:i]
		if !found {
			newReq := resolve.RequirementVersion{
				VersionKey: resolve.VersionKey{
					PackageKey:  p.PackageKey,
					Version:     p.NewVersion,
					VersionType: resolve.Requirement,
				},
			}
			newReq.Type.AddAttr(dep.MavenDependencyOrigin, "management")
			patched.Requirements = append(patched.Requirements, newReq)
		}
	}

	return patched, nil
}
