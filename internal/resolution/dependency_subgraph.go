package resolution

import (
	"context"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/v2/internal/resolution/manifest"
	"github.com/google/osv-scanner/v2/internal/resolution/util"
	"github.com/google/osv-scanner/v2/internal/utility/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type GraphNode struct {
	Version  resolve.VersionKey
	Distance int            // The shortest distance to the end Dependency Node (which has a Distance of 0)
	Parents  []resolve.Edge // Parent edges i.e. with Edge.To == this ID
	Children []resolve.Edge // Child edges i.e. with Edge.From == this ID
}

type DependencySubgraph struct {
	Dependency resolve.NodeID // The NodeID of the end dependency of this subgraph.
	Nodes      map[resolve.NodeID]GraphNode
}

// ComputeSubgraphs computes the DependencySubgraphs for each specified NodeID.
// The computed Subgraphs contains all nodes and edges that transitively depend on the specified node, and the node itself.
//
// Modifying any of the returned DependencySubgraphs may cause unexpected behaviour.
func ComputeSubgraphs(g *resolve.Graph, nodes []resolve.NodeID) []*DependencySubgraph {
	// Find the parent nodes of each node in graph, for easier traversal.
	// These slices are shared between the returned subgraphs.
	parentEdges := make(map[resolve.NodeID][]resolve.Edge)
	for _, e := range g.Edges {
		// Check for a self-dependency, just in case.
		if e.From == e.To {
			continue
		}
		parentEdges[e.To] = append(parentEdges[e.To], e)
	}

	// For each node, compute the subgraph.
	subGraphs := make([]*DependencySubgraph, 0, len(nodes))
	for _, nodeID := range nodes {
		// Starting at the node of interest, visit all unvisited parents,
		// adding the corresponding edges to the GraphNodes.
		gNodes := make(map[resolve.NodeID]GraphNode)
		seen := make(map[resolve.NodeID]struct{})
		seen[nodeID] = struct{}{}
		toProcess := []resolve.NodeID{nodeID}
		currDistance := 0 // The current distance from end dependency.
		for len(toProcess) > 0 {
			// Track the next set of nodes to process, which will be +1 Distance away from end.
			var next []resolve.NodeID
			for _, node := range toProcess {
				// Construct the GraphNode
				parents := parentEdges[node]
				gNode := gNodes[node] // Grab the existing GraphNode, which will have some Children populated.
				gNode.Version = g.Nodes[node].Version
				gNode.Distance = currDistance
				gNode.Parents = parents
				gNodes[node] = gNode
				// Populate parent's children and add to next set.
				for _, edge := range parents {
					nID := edge.From
					pNode := gNodes[nID]
					pNode.Children = append(pNode.Children, edge)
					gNodes[nID] = pNode
					if _, ok := seen[nID]; !ok {
						seen[nID] = struct{}{}
						next = append(next, nID)
					}
				}
			}
			toProcess = next
			currDistance++
		}

		subGraphs = append(subGraphs, &DependencySubgraph{
			Dependency: nodeID,
			Nodes:      gNodes,
		})
	}

	return subGraphs
}

// IsDevOnly checks if this DependencySubgraph solely contains dev (or test) dependencies.
// If groups is nil, checks the dep.Type of the direct graph edges for the Dev Attr (for in-place).
// Otherwise, uses the groups of the direct dependencies to determine if a non-dev path exists (for relax/override).
func (ds *DependencySubgraph) IsDevOnly(groups map[manifest.RequirementKey][]string) bool {
	if groups != nil {
		// Check if any of the direct dependencies are not in the dev group.
		return !slices.ContainsFunc(ds.Nodes[0].Children, func(e resolve.Edge) bool {
			req := resolve.RequirementVersion{
				VersionKey: ds.Nodes[e.To].Version,
				Type:       e.Type.Clone(),
			}

			reqGroups := groups[manifest.MakeRequirementKey(req)]
			switch req.System {
			case resolve.NPM:
				return !slices.Contains(reqGroups, "dev")
			case resolve.Maven:
				return !slices.Contains(reqGroups, "test")
			case resolve.UnknownSystem:
				fallthrough
			default:
				return true
			}
		})
	}

	// groups == nil
	// Check if any of the direct dependencies do not have the Dev attr.
	for _, e := range ds.Nodes[0].Children {
		if e.Type.HasAttr(dep.Dev) {
			continue
		}
		// As a workaround for npm workspaces, check for the Dev attr in the direct dependency's dependencies.
		for _, e2 := range ds.Nodes[e.To].Children {
			if !e2.Type.HasAttr(dep.Dev) {
				return false
			}
		}
		// If the vulnerable dependency is a direct dependency, it'd have no Children.
		// Since we've already checked that it doesn't have the Dev attr, it must be a non-dev dependency.
		if e.To == ds.Dependency {
			return false
		}
	}

	return true
}

// ConstrainingSubgraph tries to construct a subgraph of the subgraph that includes only the edges that contribute to a vulnerability.
// It identifies the dependencies which constrain the vulnerable package to use a vulnerable version.
// This is used by the 'relax' remediation strategy to identify which direct dependencies need to be updated.
//
// e.g. for a subgraph with:
//
//	A -> C@<2.0
//	B -> C@<3.0
//	C resolves to C@1.9
//
// If the vuln affecting C is fixed in version 2.0, the constraining subgraph would only contain A,
// since B would allow versions >=2.0 of C to be selected if not for A.
//
// This is a heuristic approach and may produce false positives (meaning possibly unnecessary dependencies would be flagged to be relaxed).
// If the constraining subgraph cannot be computed for some reason, returns the original DependencySubgraph.
func (ds *DependencySubgraph) ConstrainingSubgraph(ctx context.Context, cl resolve.Client, vuln *osvschema.Vulnerability) *DependencySubgraph {
	// Just check if the direct requirement of the vulnerable package is constraining it.
	// This still has some false positives.
	// e.g. if we have
	// A@* -> B@2.*
	// D@* -> B@2.1.1 -> C@1.0.0
	// resolving both together picks B@2.1.1 & thus constrains C to C@1.0.0 for A
	// But resolving A alone could pick B@2.2.0 which might not depend on C
	// Similarly, a direct dependency could be constrained by an indirect dependency with similar results.
	end := ds.Nodes[ds.Dependency]
	newParents := make([]resolve.Edge, 0, len(end.Parents))
	for _, pEdge := range end.Parents {
		// Check if the latest allowable version of the package is vulnerable
		vk := end.Version
		vk.Version = pEdge.Requirement
		vk.VersionType = resolve.Requirement
		vers, err := cl.MatchingVersions(ctx, vk)
		if err != nil || len(vers) == 0 {
			// Could not determine MatchingVersions - assume this is constraining.
			newParents = append(newParents, pEdge)
			continue
		}
		bestVK := vers[len(vers)-1] // This should be the highest version for npm

		if vulns.IsAffected(*vuln, util.VKToPackageInfo(bestVK.VersionKey)) {
			newParents = append(newParents, pEdge)
		}
	}

	if len(newParents) == 0 {
		// There has to be at least one constraining path for the vulnerability to appear.
		// If our heuristic couldn't determine any, treat the whole subgraph as constraining.
		return ds
	}

	// Rebuild the DependencySubgraph using the dependency's newParents.
	// Same logic as in ComputeSubgraphs.
	newNodes := make(map[resolve.NodeID]GraphNode)
	newNodes[ds.Dependency] = GraphNode{
		Version:  end.Version,
		Distance: 0,
		Parents:  newParents,
	}

	seen := make(map[resolve.NodeID]struct{})
	seen[ds.Dependency] = struct{}{}
	toProcess := make([]resolve.NodeID, 0, len(newParents))
	for _, e := range newParents {
		toProcess = append(toProcess, e.From)
		seen[e.From] = struct{}{}
	}

	currDistance := 1
	for len(toProcess) > 0 {
		var next []resolve.NodeID
		for _, nID := range toProcess {
			oldNode := ds.Nodes[nID]
			newNode := GraphNode{
				Version:  oldNode.Version,
				Distance: currDistance,
				Parents:  slices.Clone(oldNode.Parents),
				Children: slices.Clone(oldNode.Children),
			}
			// Remove the non-constraining edge from the node's children if it ends up in the subgraph.
			newNode.Children = slices.DeleteFunc(newNode.Children, func(e resolve.Edge) bool {
				if e.To != ds.Dependency {
					return false
				}

				return !slices.ContainsFunc(newParents, func(pEdge resolve.Edge) bool {
					return pEdge.From == e.From &&
						pEdge.Requirement == e.Requirement &&
						pEdge.Type.Compare(e.Type) == 0
				})
			})
			newNodes[nID] = newNode
			for _, e := range newNode.Parents {
				if _, ok := seen[e.From]; !ok {
					seen[e.From] = struct{}{}
					next = append(next, e.From)
				}
			}
		}
		toProcess = next
		currDistance++
	}
	// Remove children edges to nodes that are not in the computed subgraph.
	for nID, edge := range newNodes {
		edge.Children = slices.DeleteFunc(edge.Children, func(e resolve.Edge) bool {
			_, ok := seen[e.To]
			return !ok
		})
		newNodes[nID] = edge
	}

	return &DependencySubgraph{
		Dependency: ds.Dependency,
		Nodes:      newNodes,
	}
}
