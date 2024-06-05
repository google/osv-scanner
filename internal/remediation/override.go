package remediation

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/util"
	"github.com/google/osv-scanner/internal/utility/vulns"
)

// TODO: need to make a ManifestPatch with ecosystem-specific fields
type OverridePatch struct {
	resolve.PackageKey
	OrigVersion   string
	NewVersion    string
	ResolvedVulns []resolution.ResolutionVuln
}

func (p OverridePatch) String() string {
	vulns := make([]string, len(p.ResolvedVulns))
	for i, v := range p.ResolvedVulns {
		vulns[i] = v.Vulnerability.ID
	}

	return fmt.Sprintf("%s@%s -> %s %v", p.Name, p.OrigVersion, p.NewVersion, vulns)
}

type OverrideUnfixable struct {
	resolve.VersionKey
	resolution.ResolutionVuln
}

func (u OverrideUnfixable) String() string {
	return fmt.Sprintf("%s@%s [%s]", u.Name, u.Version, u.Vulnerability.ID)
}

type OverrideResult struct {
	Patches   []OverridePatch
	Unfixable []OverrideUnfixable
}

func (r OverrideResult) String() string {
	s := &strings.Builder{}
	fmt.Fprintln(s, "PATCHES:")
	for _, p := range r.Patches {
		fmt.Fprintln(s, p)
	}

	fmt.Fprintln(s, "UNFIXABLE:")
	for _, unf := range r.Unfixable {
		fmt.Fprintln(s, unf)
	}

	return s.String()
}

func ComputeOverridePatches(ctx context.Context, cl client.ResolutionClient, result *resolution.ResolutionResult, opts RemediationOptions) (OverrideResult, error) {
	// Filter the original result just in case it hasn't been already
	result.FilterVulns(opts.MatchVuln)

	// Find the vulns affecting each version key to count vulns as the scan action does.
	// TODO: Make ResolutionResult do this kind of thing.
	vkVulns := make(map[resolve.VersionKey][]*resolution.ResolutionVuln)
	for i, v := range result.Vulns {
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

	// Build the results
	var res OverrideResult
	for vk, vulnerabilities := range vkVulns {
		// Consider vulns affecting packages we don't want to change unfixable
		if slices.Contains(opts.AvoidPkgs, vk.Name) {
			for _, v := range vulnerabilities {
				res.Unfixable = append(res.Unfixable, OverrideUnfixable{VersionKey: vk, ResolutionVuln: *v})
			}

			continue
		}

		sys := vk.Semver()
		// Get & sort all the valid versions of this package
		// TODO: (Maven) skip unlisted versions and versions on other registries
		versions, err := cl.Versions(ctx, vk.PackageKey)
		if err != nil {
			return res, err
		}
		slices.SortFunc(versions, func(a, b resolve.Version) int { return sys.Compare(a.Version, b.Version) })
		vkIdx := slices.IndexFunc(versions, func(v resolve.Version) bool { return v.Version == vk.Version })

		// Find each (unique) minimal greater versions that fix each vulnerability first,
		// then determine which vulnerabilities each found version fixes.
		// Do this in two steps so a patch will include the vulnerabilities that were fixed in earlier versions.

		// Find the minimal greater versions that fix each vulnerability
		patchVersions := make(map[string]struct{})
		for _, v := range vulnerabilities {
			found := false
			for _, ver := range versions[vkIdx+1:] {
				if !opts.AllowMajor {
					if _, diff, _ := sys.Difference(vk.Version, ver.Version); diff == semver.DiffMajor {
						// Disallowed major upgrade -  stop the loop, consider this unfixable.
						break
					}
				}

				if !vulns.IsAffected(v.Vulnerability, util.VKToPackageDetails(ver.VersionKey)) {
					patchVersions[ver.Version] = struct{}{}
					found = true

					break
				}
			}
			if !found {
				res.Unfixable = append(res.Unfixable, OverrideUnfixable{VersionKey: vk, ResolutionVuln: *v})
			}
		}

		// Find the fixed vulns for each found version
		// TODO: Introduced vulns? Re-resolve to check for new dependencies?
		for ver := range patchVersions {
			patch := OverridePatch{
				PackageKey:  vk.PackageKey,
				OrigVersion: vk.Version,
				NewVersion:  ver,
			}

			for _, v := range vulnerabilities {
				if !vulns.IsAffected(v.Vulnerability, util.VKToPackageDetails(resolve.VersionKey{PackageKey: vk.PackageKey, Version: ver})) {
					patch.ResolvedVulns = append(patch.ResolvedVulns, *v)
				}
			}

			res.Patches = append(res.Patches, patch)
		}
	}

	// Sort patches for priority/consistency
	slices.SortFunc(res.Patches, func(a, b OverridePatch) int {
		// Number of vulns fixed descending
		if c := cmp.Compare(len(a.ResolvedVulns), len(b.ResolvedVulns)); c != 0 {
			return -c
		}
		// Package name ascending
		if c := cmp.Compare(a.PackageKey.Name, b.PackageKey.Name); c != 0 {
			return c
		}
		// Original version ascending
		if c := cmp.Compare(a.OrigVersion, b.OrigVersion); c != 0 {
			return c
		}
		// New version descending
		return -cmp.Compare(a.NewVersion, b.NewVersion)
	})
	slices.SortFunc(res.Unfixable, func(a, b OverrideUnfixable) int {
		if c := a.PackageKey.Compare(b.PackageKey); c != 0 {
			return c
		}
		if c := a.Semver().Compare(a.Version, b.Version); c != 0 {
			return c
		}

		return cmp.Compare(a.Vulnerability.ID, b.Vulnerability.ID)
	})

	return res, nil
}
