package resolution

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/resolve/maven"
	"deps.dev/util/resolve/npm"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	mavenutil "github.com/google/osv-scanner/internal/utility/maven"
	"github.com/google/osv-scanner/pkg/models"
)

type Vulnerability struct {
	OSV     models.Vulnerability
	DevOnly bool
	// Chains are paths through requirements from direct dependency to vulnerable package.
	// A 'Problem' chain constrains the package to a vulnerable version.
	// 'NonProblem' chains re-use the vulnerable version, but would not resolve to a vulnerable version in isolation.
	ProblemChains    []DependencyChain
	NonProblemChains []DependencyChain
}

func (rv Vulnerability) IsDirect() bool {
	fn := func(dc DependencyChain) bool { return len(dc.Edges) == 1 }
	return slices.ContainsFunc(rv.ProblemChains, fn) || slices.ContainsFunc(rv.NonProblemChains, fn)
}

type Result struct {
	Manifest        manifest.Manifest
	Graph           *resolve.Graph
	Vulns           []Vulnerability
	UnfilteredVulns []Vulnerability
}

type NodeError struct {
	NodeID resolve.NodeID
	Error  resolve.NodeError
}

func (res *Result) Errors() []NodeError {
	var errs []NodeError
	for i, n := range res.Graph.Nodes {
		for _, err := range n.Errors {
			errs = append(errs, NodeError{
				NodeID: resolve.NodeID(i),
				Error:  err,
			})
		}
	}

	return errs
}

func getResolver(sys resolve.System, cl resolve.Client) (resolve.Resolver, error) {
	switch sys { //nolint:exhaustive
	case resolve.NPM:
		return npm.NewResolver(cl), nil
	case resolve.Maven:
		return maven.NewResolver(cl), nil
	default:
		return nil, fmt.Errorf("no resolver for ecosystem %v", sys)
	}
}

type ResolveOpts struct {
	MavenManagement bool // whether to include unresolved dependencyManagement dependencies in resolved graph.
}

func Resolve(ctx context.Context, cl client.ResolutionClient, m manifest.Manifest, opts ResolveOpts) (*Result, error) {
	c := client.NewOverrideClient(cl.DependencyClient)
	c.AddVersion(m.Root, m.Requirements)
	for _, loc := range m.LocalManifests {
		c.AddVersion(loc.Root, loc.Requirements)
		// TODO: may need to do this recursively
	}
	cl.DependencyClient = c
	r, err := getResolver(m.System(), cl.DependencyClient)
	if err != nil {
		return nil, err
	}

	graph, err := r.Resolve(ctx, m.Root.VersionKey)
	if err != nil {
		return nil, err
	}
	graph, err = resolvePostProcess(ctx, cl, m, opts, graph)
	if err != nil {
		return nil, err
	}

	if len(graph.Error) > 0 {
		return nil, errors.New(graph.Error)
	}

	result := &Result{
		Manifest: m.Clone(),
		Graph:    graph,
	}

	if err := result.computeVulns(ctx, cl); err != nil {
		return nil, err
	}

	// Make a copy of the found vulns, as `Vulns` may be filtered according to specified criteria.
	result.UnfilteredVulns = slices.Clone(result.Vulns)

	return result, nil
}

func resolvePostProcess(ctx context.Context, cl client.ResolutionClient, m manifest.Manifest, opts ResolveOpts, graph *resolve.Graph) (*resolve.Graph, error) {
	if m.System() == resolve.Maven && opts.MavenManagement {
		// Add a node & edge for each dependency in dependencyManagement that doesn't already appear in the resolved graph
		manifestSpecific, ok := m.EcosystemSpecific.(manifest.MavenManifestSpecific)
		if !ok {
			return graph, errors.New("invalid MavenManifestSpecific data")
		}

		// Search through OriginalRequirements management dependencies in this pom only (not parents).
		// TODO: Possibly refactor RequirementsForUpdates for this purpose.
		for _, req := range manifestSpecific.OriginalRequirements {
			if req.Origin != mavenutil.OriginManagement {
				// TODO: also check management in activated profiles and dependencies in inactive profiles.
				continue
			}

			// Unique identifier for this package.
			reqKey := manifest.MakeRequirementKey(resolve.RequirementVersion{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   req.Name(),
					},
					VersionType: resolve.Requirement,
					Version:     string(req.Version),
				},
				Type: resolve.MavenDepType(req.Dependency, req.Origin),
			})

			// Find the current version of the dependencyManagement dependency, after property interpolation & changes from remediation.
			idx := slices.IndexFunc(m.Requirements, func(rv resolve.RequirementVersion) bool {
				if origin, _ := rv.Type.GetAttr(dep.MavenDependencyOrigin); origin != mavenutil.OriginManagement {
					return false
				}

				return reqKey == manifest.MakeRequirementKey(rv)
			})

			if idx == -1 {
				// Ideally, this would be an error, but there a few known instances where this lookup fails:
				// 1. The artifact name contain a property (properties aren't substituted in OriginalRequirements, but are in Manifest.Requirements)
				// 2. Missing properties (due to e.g. un-activated profiles) cause the dependency to be invalid, and therefore excluded from Manifest.Requirements.
				// Ignore these dependencies in these cases so that we can still remediation vulns in the other packages.
				// TODO: logging
				continue
			}

			rv := m.Requirements[idx]

			// See if the package is already in the resolved graph.
			// Check the edges so we can make sure the ArtifactTypes and Classifiers match.
			if !slices.ContainsFunc(graph.Edges, func(e resolve.Edge) bool {
				return reqKey == manifest.MakeRequirementKey(resolve.RequirementVersion{
					VersionKey: graph.Nodes[e.To].Version,
					Type:       e.Type,
				})
			}) {
				// Management dependency not in graph - create the node.
				// Find the version the management requirement would resolve to.
				// First assume it's a soft requirement.
				vk := rv.VersionKey
				vk.VersionType = resolve.Concrete
				if _, err := cl.Version(ctx, vk); err != nil {
					// Not a soft requirement - try find a match.
					vk.VersionType = resolve.Requirement
					vks, err := cl.MatchingVersions(ctx, vk)
					if err != nil || len(vks) == 0 {
						err = graph.AddError(0, vk, fmt.Sprintf("could not find a version that satisfies requirement %s for package %s", vk.Version, vk.Name))
						if err != nil {
							return nil, err
						}

						continue
					}
					vk = vks[len(vks)-1].VersionKey
				}
				// Add the node & and edge from the root.
				nID := graph.AddNode(vk)
				if err := graph.AddEdge(0, nID, rv.Version, rv.Type.Clone()); err != nil {
					return nil, err
				}
			}
		}
	}

	return graph, nil
}

// computeVulns scans for vulnerabilities in a resolved graph and populates res.Vulns
func (res *Result) computeVulns(ctx context.Context, cl client.ResolutionClient) error {
	nodeVulns, err := cl.FindVulns(res.Graph)
	if err != nil {
		return err
	}
	// Find all dependency paths to the vulnerable dependencies
	var vulnerableNodes []resolve.NodeID
	vulnInfo := make(map[string]models.Vulnerability)
	for i, vulns := range nodeVulns {
		if len(vulns) > 0 {
			vulnerableNodes = append(vulnerableNodes, resolve.NodeID(i))
		}
		for _, vuln := range vulns {
			vulnInfo[vuln.ID] = vuln
		}
	}

	nodeChains := ComputeChains(res.Graph, vulnerableNodes)
	vulnChains := make(map[string][]DependencyChain)
	for i, idx := range vulnerableNodes {
		for _, vuln := range nodeVulns[idx] {
			vulnChains[vuln.ID] = append(vulnChains[vuln.ID], nodeChains[i]...)
		}
	}

	// construct the resolution.Vulnerability
	// TODO: This constructs a single resolution.Vulnerability per vulnerability ID.
	// The scan action treats vulns with the same ID but affecting different versions of a package as distinct.
	// TODO: Combine aliased IDs
	for id, vuln := range vulnInfo {
		rv := Vulnerability{OSV: vuln, DevOnly: true}
		for _, chain := range vulnChains[id] {
			if chainConstrains(ctx, cl, chain, &rv.OSV) {
				rv.ProblemChains = append(rv.ProblemChains, chain)
			} else {
				rv.NonProblemChains = append(rv.NonProblemChains, chain)
			}
			rv.DevOnly = rv.DevOnly && ChainIsDev(chain, res.Manifest.Groups)
		}
		if len(rv.ProblemChains) == 0 {
			// There has to be at least one problem chain for the vulnerability to appear.
			// If our heuristic couldn't determine any, treat them all as problematic.
			rv.ProblemChains = rv.NonProblemChains
			rv.NonProblemChains = nil
		}
		res.Vulns = append(res.Vulns, rv)
	}

	return nil
}

// FilterVulns populates Vulns with the UnfilteredVulns that satisfy matchFn
func (res *Result) FilterVulns(matchFn func(Vulnerability) bool) {
	var matchedVulns []Vulnerability
	for _, v := range res.UnfilteredVulns {
		if matchFn(v) {
			matchedVulns = append(matchedVulns, v)
		}
	}
	res.Vulns = matchedVulns
}

type Difference struct {
	Original     *Result
	New          *Result
	RemovedVulns []Vulnerability
	AddedVulns   []Vulnerability
	manifest.Patch
}

func (res *Result) CalculateDiff(other *Result) Difference {
	diff := Difference{
		Original: res,
		New:      other,
		Patch:    manifest.Patch{Manifest: &res.Manifest},
	}
	// Find the changed requirements and the versions they resolve to
	for i, oldReq := range res.Manifest.Requirements { // assuming these are in the same order and none are added/removed
		newReq := other.Manifest.Requirements[i]
		if oldReq.Version == newReq.Version {
			continue
		}
		// Find the node in the graph to find which actual version it resolved to
		var oldResolved string
		for _, e := range res.Graph.Edges {
			toNode := res.Graph.Nodes[e.To]
			if e.From == 0 && toNode.Version.PackageKey == oldReq.PackageKey {
				oldResolved = toNode.Version.Version
				break
			}
		}
		var newResolved string
		for _, e := range other.Graph.Edges {
			toNode := other.Graph.Nodes[e.To]
			if e.From == 0 && toNode.Version.PackageKey == newReq.PackageKey {
				newResolved = toNode.Version.Version
				break
			}
		}
		diff.Deps = append(diff.Deps, manifest.DependencyPatch{
			Pkg:          oldReq.PackageKey,
			Type:         oldReq.Type.Clone(),
			OrigRequire:  oldReq.Version,
			OrigResolved: oldResolved,
			NewRequire:   newReq.Version,
			NewResolved:  newResolved,
		})
	}

	// Compute differences in present vulnerabilities.
	// Currently this relies on vulnerability IDs being unique in the Vulns slice.
	oldVulns := make(map[string]int, len(res.Vulns))
	for i, v := range res.Vulns {
		oldVulns[v.OSV.ID] = i
	}
	for _, v := range other.Vulns {
		if _, ok := oldVulns[v.OSV.ID]; ok {
			// The vuln already existed.
			delete(oldVulns, v.OSV.ID) // delete so we know what's been removed
		} else {
			// This vuln was not in the original resolution - it was newly added
			diff.AddedVulns = append(diff.AddedVulns, v)
		}
	}
	// Any remaining oldVulns have been removed in the new resolution
	for _, idx := range oldVulns {
		diff.RemovedVulns = append(diff.RemovedVulns, res.Vulns[idx])
	}

	return diff
}

// Compare compares ResolutionDiffs based on 'effectiveness' (best first):
//
// Sort order:
//  1. (number of fixed vulns - introduced vulns) / (number of changed direct dependencies) [descending]
//     (i.e. more efficient first)
//  2. number of fixed vulns [descending]
//  3. number of changed direct dependencies [ascending]
//  4. changed direct dependency name package names [ascending]
//  5. size of changed direct dependency bump [ascending]
func (a Difference) Compare(b Difference) int {
	// 1. (fixed - introduced) / (changes) [desc]
	// Multiply out to avoid float casts
	aRatio := (len(a.RemovedVulns) - len(a.AddedVulns)) * (len(b.Deps))
	bRatio := (len(b.RemovedVulns) - len(b.AddedVulns)) * (len(a.Deps))
	if c := cmp.Compare(aRatio, bRatio); c != 0 {
		return -c
	}

	// 2. number of fixed vulns [desc]
	if c := cmp.Compare(len(a.RemovedVulns), len(b.RemovedVulns)); c != 0 {
		return -c
	}

	// 3. number of changed deps [asc]
	if c := cmp.Compare(len(a.Deps), len(b.Deps)); c != 0 {
		return c
	}

	// 4. changed names [asc]
	for i, aDep := range a.Deps {
		bDep := b.Deps[i]
		if c := aDep.Pkg.Compare(bDep.Pkg); c != 0 {
			return c
		}
	}

	// 5. dependency bump amount [asc]
	for i, aDep := range a.Deps {
		bDep := b.Deps[i]
		sv := aDep.Pkg.Semver()
		if c := sv.Compare(aDep.NewResolved, bDep.NewResolved); c != 0 {
			return c
		}
	}

	return 0
}
