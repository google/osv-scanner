package fix

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/resolution"
	lf "github.com/google/osv-scanner/internal/resolution/lockfile"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
)

func autoInPlace(ctx context.Context, r reporter.Reporter, opts osvFixOptions, maxUpgrades int) error {
	r.Infof("Scanning %s...\n", opts.Lockfile)
	f, err := lockfile.OpenLocalDepFile(opts.Lockfile)
	if err != nil {
		return err
	}

	g, err := opts.LockfileRW.Read(f)
	f.Close()
	if err != nil {
		return err
	}

	res, err := remediation.ComputeInPlacePatches(ctx, opts.Client, g, opts.RemediationOptions)
	if err != nil {
		return err
	}

	patches, nFixed, nRemain := autoChooseInPlacePatches(res, maxUpgrades)
	totalVulns := nFixed + nRemain + len(res.Unfixable)

	r.Infof("Found %d vulnerabilities matching the filter\n", totalVulns)
	r.Infof("Can fix %d/%d matching vulnerabilities by changing %d dependencies\n", nFixed, totalVulns, len(patches))

	for _, p := range patches {
		r.Infof("UPGRADED-PACKAGE: %s,%s,%s\n", p.Pkg.Name, p.OrigVersion, p.NewVersion)
	}
	r.Infof("REMAINING-VULNS: %d\n", totalVulns-nFixed)
	r.Infof("UNFIXABLE-VULNS: %d\n", len(res.Unfixable))

	r.Infof("Rewriting %s...\n", opts.Lockfile)

	return lf.Overwrite(opts.LockfileRW, opts.Lockfile, patches)
}

// returns the top {maxUpgrades} compatible patches, the number of vulns fixed, and the number of potentially fixable vulns left unfixed
// if maxUpgrades is -1, do as many patches as possible
func autoChooseInPlacePatches(res remediation.InPlaceResult, maxUpgrades int) ([]lf.DependencyPatch, int, int) {
	seenVKs := make(map[resolve.VersionKey]struct{})
	type vulnKey struct {
		id string
		vk resolve.VersionKey
	}
	uniqueVulns := make(map[vulnKey]struct{})
	var patches []lf.DependencyPatch
	numFixed := 0

	for _, p := range res.Patches {
		vk := resolve.VersionKey{
			PackageKey: p.Pkg,
			Version:    p.OrigVersion,
		}

		if _, seen := seenVKs[vk]; maxUpgrades != 0 && !seen {
			seenVKs[vk] = struct{}{}
			patches = append(patches, p.DependencyPatch)
			if maxUpgrades != -1 {
				maxUpgrades--
			}
			numFixed += len(p.ResolvedVulns)
		}

		for _, rv := range p.ResolvedVulns {
			uniqueVulns[vulnKey{id: rv.Vulnerability.ID, vk: vk}] = struct{}{}
		}
	}

	return patches, numFixed, len(uniqueVulns) - numFixed
}

func autoRelock(ctx context.Context, r reporter.Reporter, opts osvFixOptions, maxUpgrades int) error {
	r.Infof("Resolving %s...\n", opts.Manifest)
	f, err := lockfile.OpenLocalDepFile(opts.Manifest)
	if err != nil {
		return err
	}

	manif, err := opts.ManifestRW.Read(f)
	f.Close()
	if err != nil {
		return err
	}

	opts.Client.PreFetch(ctx, manif.Requirements, manif.FilePath)
	res, err := resolution.Resolve(ctx, opts.Client, manif)
	if err != nil {
		return err
	}

	if errs := res.Errors(); len(errs) > 0 {
		r.Warnf("WARNING: encountered %d errors during dependency resolution:\n", len(errs))
		r.Warnf(resolutionErrorString(res, errs))
	}

	res.FilterVulns(opts.MatchVuln)
	// TODO: count vulnerabilities per unique version as scan action does
	totalVulns := len(res.Vulns)
	r.Infof("Found %d vulnerabilities matching the filter\n", totalVulns)

	allPatches, err := remediation.ComputeRelaxPatches(ctx, opts.Client, res, opts.RemediationOptions)
	if err != nil {
		return err
	}

	if err := opts.Client.WriteCache(manif.FilePath); err != nil {
		r.Warnf("WARNING: failed to write resolution cache: %v\n", err)
	}

	if len(allPatches) == 0 {
		r.Infof("No dependency patches are possible\n")
		r.Infof("REMAINING-VULNS: %d\n", totalVulns)
		r.Infof("UNFIXABLE-VULNS: %d\n", totalVulns)

		return nil
	}

	depPatches, nFixed, nUnfixable := autoChooseRelockPatches(allPatches, maxUpgrades)
	r.Infof("Can fix %d/%d matching vulnerabilities by changing %d dependencies\n", nFixed, totalVulns, len(depPatches))
	for _, p := range depPatches {
		r.Infof("UPGRADED-PACKAGE: %s,%s,%s\n", p.Pkg.Name, p.OrigRequire, p.NewRequire)
	}
	r.Infof("REMAINING-VULNS: %d\n", totalVulns-nFixed)
	r.Infof("UNFIXABLE-VULNS: %d\n", nUnfixable)

	r.Infof("Rewriting %s...\n", opts.Manifest)
	if err := manifest.Overwrite(opts.ManifestRW, opts.Manifest, manifest.ManifestPatch{Manifest: &manif, Deps: depPatches}); err != nil {
		return err
	}

	if opts.Lockfile != "" || opts.RelockCmd != "" {
		// We only recreate the lockfile if we know a lockfile already exists
		// or we've been given a command to run.
		r.Infof("Shelling out to regenerate lockfile...\n")
		return regenerateLockfile(r, opts)
	}

	return nil
}

// returns the top {maxUpgrades} compatible patches, the number of vulns fixed, and the number unfixable vulns
// if maxUpgrades is -1, do as many patches as possible
func autoChooseRelockPatches(diffs []resolution.ResolutionDiff, maxUpgrades int) ([]manifest.DependencyPatch, int, int) {
	unfixableVulnIDs := make(map[string]struct{})
	for _, v := range diffs[0].Original.Vulns {
		unfixableVulnIDs[v.Vulnerability.ID] = struct{}{}
	}

	var patches []manifest.DependencyPatch
	pkgChanged := make(map[resolve.VersionKey]bool)
	numFixed := 0

	for _, diff := range diffs {
		for _, v := range diff.RemovedVulns {
			delete(unfixableVulnIDs, v.Vulnerability.ID)
		}

		if maxUpgrades == 0 || slices.ContainsFunc(diff.Deps, func(dp manifest.DependencyPatch) bool {
			return pkgChanged[resolve.VersionKey{PackageKey: dp.Pkg, Version: dp.OrigRequire}]
		}) {
			continue
		}

		numFixed += len(diff.RemovedVulns)
		for _, dp := range diff.Deps {
			patches = append(patches, dp)
			pkgChanged[resolve.VersionKey{PackageKey: dp.Pkg, Version: dp.OrigRequire}] = true
		}
		if maxUpgrades != -1 {
			maxUpgrades--
		}
	}

	return patches, numFixed, len(unfixableVulnIDs)
}

func resolutionErrorString(res *resolution.ResolutionResult, errs []resolution.ResolutionError) string {
	// we pass in the []ResolutionErrors because calling res.Errors() is costly
	s := strings.Builder{}
	for _, e := range errs {
		node := res.Graph.Nodes[e.NodeID]
		fmt.Fprintf(&s, "Error when resolving %s@%s:\n", node.Version.Name, node.Version.Version)
		req := e.Error.Req
		if strings.Contains(req.Version, ":") {
			// this will be the case with unsupported npm requirements e.g. `file:...`, `git+https://...`
			// TODO: don't rely on resolution to propagate these errors
			// No easy access to the `knownAs` field to find which package this corresponds to
			fmt.Fprintf(&s, "\tSkipped resolving unsupported version specification: %s\n", req.Version)
		} else {
			fmt.Fprintf(&s, "\t%v: %s@%s\n", e.Error.Error, req.Name, req.Version)
		}
	}

	return s.String()
}
