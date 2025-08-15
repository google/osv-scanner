package fix

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/datasource"
	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/internal/remediation"
	"github.com/google/osv-scanner/v2/internal/resolution"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/google/osv-scanner/v2/internal/resolution/depfile"
	lf "github.com/google/osv-scanner/v2/internal/resolution/lockfile"
	"github.com/google/osv-scanner/v2/internal/resolution/manifest"
	"github.com/google/osv-scanner/v2/internal/resolution/util"
)

func autoInPlace(ctx context.Context, opts osvFixOptions, maxUpgrades int) error {
	if !remediation.SupportsInPlace(opts.LockfileRW) {
		return fmt.Errorf("%s strategy is not supported for lockfile", strategyInPlace)
	}

	cmdlogger.Infof("Scanning %s...", opts.Lockfile)
	var outputResult fixOutput
	outputResult.Path = opts.Lockfile
	outputResult.Ecosystem = util.OSVEcosystem[opts.LockfileRW.System()]
	outputResult.Strategy = strategyInPlace

	f, err := depfile.OpenLocalDepFile(opts.Lockfile)
	if err != nil {
		return err
	}

	g, err := opts.LockfileRW.Read(f)
	f.Close()
	if err != nil {
		return err
	}

	res, err := remediation.ComputeInPlacePatches(ctx, opts.Client, g, opts.Options)
	if err != nil {
		return err
	}

	patches := autoChooseInPlacePatches(res, maxUpgrades, &outputResult)

	if err := printResult(outputResult, opts); err != nil {
		cmdlogger.Errorf("failed writing output")
		return err
	}

	cmdlogger.Infof("Rewriting %s...", opts.Lockfile)

	return lf.Overwrite(opts.LockfileRW, opts.Lockfile, patches)
}

// returns the top {maxUpgrades} compatible patches, and populates outputResult.
// if maxUpgrades is < 0, do as many patches as possible
func autoChooseInPlacePatches(res remediation.InPlaceResult, maxUpgrades int, outputResult *fixOutput) []lf.DependencyPatch {
	// Keep track of the VersionKeys we've already patched so we know which patches are incompatible
	seenVKs := make(map[resolve.VersionKey]bool)

	uniqueVulns := make(map[packageOutput]struct{})
	var patches []lf.DependencyPatch

	for _, p := range res.Patches {
		vk := resolve.VersionKey{
			PackageKey: p.Pkg,
			Version:    p.OrigVersion,
		}

		// add each of the resolved vulnKeys to the set of unique vulns
		for _, rv := range p.ResolvedVulns {
			p := packageOutput{Name: vk.Name, Version: vk.Version}
			if _, ok := uniqueVulns[p]; ok {
				continue
			}
			uniqueVulns[p] = struct{}{}
			outputResult.Vulnerabilities = append(outputResult.Vulnerabilities, vulnOutput{
				ID:           rv.OSV.ID,
				Packages:     []packageOutput{p},
				Unactionable: false,
			})
		}

		// If we still are picking more patches, and we haven't already patched this specific version,
		// then add this patch to our final set of patches and count the vulnerabilities
		if maxUpgrades != 0 && !seenVKs[vk] {
			seenVKs[vk] = true
			patches = append(patches, p.DependencyPatch)
			maxUpgrades--

			vulns := make([]vulnOutput, len(p.ResolvedVulns))
			for i, v := range p.ResolvedVulns {
				vulns[i].ID = v.OSV.ID
				vulns[i].Packages = []packageOutput{{Name: p.Pkg.Name, Version: p.OrigVersion}}
				vulns[i].Unactionable = false
			}
			sortVulns(vulns)
			outputResult.Patches = append(outputResult.Patches, patchOutput{
				PackageUpdates: []updatePackageOutput{{Name: p.Pkg.Name, VersionFrom: p.OrigVersion, VersionTo: p.NewVersion, Transitive: true}},
				Fixed:          vulns,
			})
		}
	}

	// Add unactionable vulns to output
	for _, vuln := range res.Unfixable {
		v := makeResultVuln(vuln)
		v.Unactionable = true
		outputResult.Vulnerabilities = append(outputResult.Vulnerabilities, v)
	}
	sortVulns(outputResult.Vulnerabilities)

	return patches
}

func autoRelax(ctx context.Context, opts osvFixOptions, maxUpgrades int) error {
	if !remediation.SupportsRelax(opts.ManifestRW) {
		return fmt.Errorf("%s strategy is not supported for manifest", strategyRelax)
	}

	cmdlogger.Infof("Resolving %s...", opts.Manifest)
	var outputResult fixOutput
	outputResult.Path = opts.Manifest
	outputResult.Ecosystem = util.OSVEcosystem[opts.ManifestRW.System()]
	outputResult.Strategy = strategyRelax

	f, err := depfile.OpenLocalDepFile(opts.Manifest)
	if err != nil {
		return err
	}

	manif, err := opts.ManifestRW.Read(f)
	f.Close()
	if err != nil {
		return err
	}

	client.PreFetch(ctx, opts.Client, manif.Requirements, manif.FilePath)
	res, err := resolution.Resolve(ctx, opts.Client, manif, opts.ResolveOpts)
	if err != nil {
		return err
	}

	res.FilterVulns(opts.MatchVuln)
	// TODO: count vulnerabilities per unique version as scan action does

	allPatches, err := remediation.ComputeRelaxPatches(ctx, opts.Client, res, opts.Options)
	if err != nil {
		return err
	}

	if opts.NoIntroduce {
		allPatches = removeVulnIntroducingPatches(allPatches)
	}

	populateResultVulns(&outputResult, res, allPatches)

	if err := opts.Client.WriteCache(manif.FilePath); err != nil {
		cmdlogger.Warnf("WARNING: failed to write resolution cache: %v", err)
	}

	depPatches := autoChooseRelaxPatches(allPatches, maxUpgrades, &outputResult)

	if err := printResult(outputResult, opts); err != nil {
		cmdlogger.Errorf("failed writing output")
		return err
	}

	if len(depPatches) == 0 {
		return nil
	}

	cmdlogger.Infof("Rewriting %s...", opts.Manifest)
	if err := manifest.Overwrite(opts.ManifestRW, opts.Manifest, manifest.Patch{Manifest: &manif, Deps: depPatches}); err != nil {
		return err
	}

	if opts.Lockfile != "" {
		// We only recreate the lockfile if we know a lockfile already exists
		// or we've been given a command to run.
		cmdlogger.Infof("Shelling out to regenerate lockfile...")
		cmd, err := regenerateLockfileCmd(ctx, opts)
		if err != nil {
			return err
		}

		cmd.Stdout = opts.Stdout
		cmd.Stderr = opts.Stderr
		cmdlogger.Infof("Executing `%s`...", cmd)
		err = cmd.Run()
		if err == nil {
			return nil
		}

		cmdlogger.Warnf("Install failed. Trying again with `--legacy-peer-deps`...")
		cmd, err = regenerateLockfileCmd(ctx, opts)
		if err != nil {
			return err
		}
		cmd.Args = append(cmd.Args, "--legacy-peer-deps")
		cmd.Stdout = opts.Stdout
		cmd.Stderr = opts.Stderr

		return cmd.Run()
	}

	return nil
}

// returns the top {maxUpgrades} compatible patches, and populates outputResult
// if maxUpgrades is < 0, do as many patches as possible
func autoChooseRelaxPatches(diffs []resolution.Difference, maxUpgrades int, outputResult *fixOutput) []manifest.DependencyPatch {
	var patches []manifest.DependencyPatch
	pkgChanged := make(map[resolve.VersionKey]bool) // dependencies we've already applied a patch to

	for _, diff := range diffs {
		// If we are not picking any more patches, or this patch is incompatible with existing patches, skip adding it to the patch list.
		// A patch is incompatible if any of its changed packages have already been changed by an existing patch.
		if maxUpgrades == 0 || slices.ContainsFunc(diff.Deps, func(dp manifest.DependencyPatch) bool {
			return pkgChanged[resolve.VersionKey{PackageKey: dp.Pkg, Version: dp.OrigRequire}]
		}) {
			continue
		}

		var p patchOutput
		// Add all individual package patches to the final patch list, and add the vulns this is anticipated to resolve
		for _, dp := range diff.Deps {
			patches = append(patches, dp)
			pkgChanged[resolve.VersionKey{PackageKey: dp.Pkg, Version: dp.OrigRequire}] = true
			p.PackageUpdates = append(p.PackageUpdates, updatePackageOutput{
				Name:        dp.Pkg.Name,
				VersionFrom: dp.OrigRequire,
				VersionTo:   dp.NewRequire,
				Transitive:  false,
			})
		}
		for _, vuln := range diff.RemovedVulns {
			p.Fixed = append(p.Fixed, makeResultVuln(vuln))
		}
		sortVulns(p.Fixed)
		for _, v := range diff.AddedVulns {
			p.Introduced = append(p.Introduced, makeResultVuln(v))
		}
		sortVulns(p.Introduced)
		outputResult.Patches = append(outputResult.Patches, p)
		maxUpgrades--
	}

	return patches
}

func autoOverride(ctx context.Context, opts osvFixOptions, maxUpgrades int) error {
	if !remediation.SupportsOverride(opts.ManifestRW) {
		return errors.New("override strategy is not supported for manifest")
	}

	cmdlogger.Infof("Resolving %s...", opts.Manifest)
	var outputResult fixOutput
	outputResult.Path = opts.Manifest
	outputResult.Ecosystem = util.OSVEcosystem[opts.ManifestRW.System()]
	outputResult.Strategy = strategyOverride
	f, err := depfile.OpenLocalDepFile(opts.Manifest)
	if err != nil {
		return err
	}

	manif, err := opts.ManifestRW.Read(f)
	f.Close()
	if err != nil {
		return err
	}

	if opts.ManifestRW.System() == resolve.Maven {
		// Update Maven registries based on the repositories defined in pom.xml,
		// as well as the repositories merged from parent pom.xml.
		// TODO: add registries defined in settings.xml
		// https://github.com/google/osv-scanner/issues/1269
		specific, ok := manif.EcosystemSpecific.(manifest.MavenManifestSpecific)
		if ok {
			registries := make([]client.Registry, len(specific.Repositories))
			for i, repo := range specific.Repositories {
				registries[i] = datasource.MavenRegistry{
					URL:              string(repo.URL),
					ID:               string(repo.ID),
					ReleasesEnabled:  repo.Releases.Enabled.Boolean(),
					SnapshotsEnabled: repo.Snapshots.Enabled.Boolean(),
				}
			}
			if err := opts.Client.AddRegistries(registries); err != nil {
				return err
			}
		}
	}
	client.PreFetch(ctx, opts.Client, manif.Requirements, manif.FilePath)
	res, err := resolution.Resolve(ctx, opts.Client, manif, opts.ResolveOpts)
	if err != nil {
		return err
	}

	res.FilterVulns(opts.MatchVuln)
	// TODO: count vulnerabilities per unique version as scan action does

	allPatches, err := remediation.ComputeOverridePatches(ctx, opts.Client, res, opts.Options)
	if err != nil {
		return err
	}

	if opts.NoIntroduce {
		allPatches = removeVulnIntroducingPatches(allPatches)
	}

	populateResultVulns(&outputResult, res, allPatches)

	if err := opts.Client.WriteCache(manif.FilePath); err != nil {
		cmdlogger.Warnf("WARNING: failed to write resolution cache: %v", err)
	}

	depPatches := autoChooseOverridePatches(allPatches, maxUpgrades, &outputResult)

	if err := printResult(outputResult, opts); err != nil {
		cmdlogger.Errorf("failed writing output")
		return err
	}

	if len(depPatches) == 0 {
		return nil
	}

	cmdlogger.Infof("Rewriting %s...", opts.Manifest)
	if err := manifest.Overwrite(opts.ManifestRW, opts.Manifest, manifest.Patch{Manifest: &manif, Deps: depPatches}); err != nil {
		return err
	}

	return nil
}

func autoChooseOverridePatches(diffs []resolution.Difference, maxUpgrades int, outputResult *fixOutput) []manifest.DependencyPatch {
	if maxUpgrades == 0 {
		return nil
	}

	var patches []manifest.DependencyPatch
	pkgChanged := make(map[resolve.PackageKey]bool) // dependencies we've already applied a patch to
	fixedVulns := make(map[string]struct{})         // vulns that have already been fixed by a patch
	for _, diff := range diffs {
		// If this patch is incompatible with existing patches, skip adding it to the patch list.

		// A patch is incompatible if any of its changed packages have already been changed by an existing patch.
		if slices.ContainsFunc(diff.Deps, func(dp manifest.DependencyPatch) bool { return pkgChanged[dp.Pkg] }) {
			continue
		}
		// A patch is also incompatible if any fixed vulnerability has already been fixed by another patch.
		// This would happen if updating the version of one package has a side effect of also updating or removing one of its vulnerable dependencies.
		// e.g. We have {foo@1 -> bar@1}, and two possible patches [foo@3, bar@2].
		// Patching foo@3 makes {foo@3 -> bar@3}, which also fixes the vulnerability in bar.
		// Applying both patches would force {foo@3 -> bar@2}, which is less desirable.
		if slices.ContainsFunc(diff.RemovedVulns, func(rv resolution.Vulnerability) bool { _, ok := fixedVulns[rv.OSV.ID]; return ok }) {
			continue
		}

		var p patchOutput
		// Add all individual package patches to the final patch list, and track the vulns this is anticipated to fix.
		for _, dp := range diff.Deps {
			patches = append(patches, dp)
			pkgChanged[dp.Pkg] = true

			pkgUpdate := updatePackageOutput{
				Name:        dp.Pkg.Name,
				VersionFrom: dp.OrigResolved,
				VersionTo:   dp.NewRequire,
				Transitive:  true,
			}
			// Check if this is a direct dependency
			for _, req := range diff.Original.Manifest.Requirements {
				if req.PackageKey == dp.Pkg && !req.Type.HasAttr(dep.MavenDependencyOrigin) {
					pkgUpdate.Transitive = false
					break
				}
			}
			p.PackageUpdates = append(p.PackageUpdates, pkgUpdate)
		}
		for _, vuln := range diff.RemovedVulns {
			fixedVulns[vuln.OSV.ID] = struct{}{}
			p.Fixed = append(p.Fixed, makeResultVuln(vuln))
		}
		sortVulns(p.Fixed)
		for _, vuln := range diff.AddedVulns {
			p.Introduced = append(p.Introduced, makeResultVuln(vuln))
		}
		sortVulns(p.Introduced)
		outputResult.Patches = append(outputResult.Patches, p)

		maxUpgrades--
		if maxUpgrades == 0 {
			break
		}
	}

	return patches
}

func sortVulns(vulns []vulnOutput) {
	slices.SortFunc(vulns, func(a, b vulnOutput) int {
		return identifiers.IDSortFunc(a.ID, b.ID)
	})
}

func makeResultVuln(vuln resolution.Vulnerability) vulnOutput {
	v := vulnOutput{
		ID: vuln.OSV.ID,
	}

	affected := make(map[packageOutput]struct{})
	for _, sg := range vuln.Subgraphs {
		vk := sg.Nodes[sg.Dependency].Version
		affected[packageOutput{Name: vk.Name, Version: vk.Version}] = struct{}{}
	}
	v.Packages = slices.AppendSeq(make([]packageOutput, 0, len(affected)), maps.Keys(affected))
	slices.SortFunc(v.Packages, func(a, b packageOutput) int {
		if c := cmp.Compare(a.Name, b.Name); c != 0 {
			return c
		}

		return cmp.Compare(a.Version, b.Version)
	})

	return v
}

func populateResultVulns(outputResult *fixOutput, res *resolution.Result, allPatches []resolution.Difference) {
	// Resolution errors
	for _, err := range res.Errors() {
		node := res.Graph.Nodes[err.NodeID]
		outputResult.Errors = append(outputResult.Errors, errorOutput{
			Package: packageOutput{
				Name:    node.Version.Name,
				Version: node.Version.Version,
			},
			Requirement: packageOutput{
				Name:    err.Error.Req.Name,
				Version: err.Error.Req.Version,
			},
			Error: err.Error.Error,
		})
	}

	// Vulnerabilities
	vulns := make(map[string]vulnOutput, len(res.Vulns))
	outputResult.Vulnerabilities = make([]vulnOutput, len(res.Vulns))
	for _, vuln := range res.Vulns {
		v := makeResultVuln(vuln)
		v.Unactionable = true
		vulns[v.ID] = v
	}

	// Determine if vulnerabilities are actionable
	for _, p := range allPatches {
		for _, vuln := range p.RemovedVulns {
			if v, ok := vulns[vuln.OSV.ID]; ok {
				v.Unactionable = false
				vulns[vuln.OSV.ID] = v
			}
		}
	}

	outputResult.Vulnerabilities = slices.Collect(maps.Values(vulns))
	sortVulns(outputResult.Vulnerabilities)
}

func removeVulnIntroducingPatches(patches []resolution.Difference) []resolution.Difference {
	return slices.DeleteFunc(patches, func(diff resolution.Difference) bool { return len(diff.AddedVulns) > 0 })
}
