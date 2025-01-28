package resolution

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/resolution/util"
	vulnUtil "github.com/google/osv-scanner/internal/utility/vulns"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
)

type GraphNode struct {
	Version  resolve.VersionKey
	Distance int
	Parents  []resolve.Edge
	Children []resolve.Edge
}

type DependencySubgraph struct {
	Dependency resolve.NodeID
	Nodes      map[resolve.NodeID]GraphNode
}

func (ds *DependencySubgraph) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[%d: %s]\n", ds.Dependency, ds.Nodes[ds.Dependency].Version)
	for nID, n := range ds.Nodes {
		for _, p := range n.Parents {
			fmt.Fprintf(&sb, "%d@%s ", p.From, p.Requirement)
		}
		fmt.Fprintf(&sb, "-> %d: %s (%d) ->", nID, n.Version, n.Distance)
		for _, c := range n.Children {
			fmt.Fprintf(&sb, " %d@%s", c.To, c.Requirement)
		}
		fmt.Fprintln(&sb)
	}

	return sb.String()
}

func ComputeSubgraphs(g *resolve.Graph, nodes []resolve.NodeID) []*DependencySubgraph {
	// find the parent nodes of each node in graph, for easier traversal
	parentEdges := make(map[resolve.NodeID][]resolve.Edge)
	for _, e := range g.Edges {
		// check for a self-dependency, just in case
		if e.From == e.To {
			continue
		}
		parentEdges[e.To] = append(parentEdges[e.To], e)
	}

	subGraphs := make([]*DependencySubgraph, 0, len(nodes))
	for _, nodeID := range nodes {
		gNodes := make(map[resolve.NodeID]GraphNode)

		seen := make(map[resolve.NodeID]struct{})
		seen[nodeID] = struct{}{}
		toProcess := []resolve.NodeID{nodeID}
		currDistance := 0
		for len(toProcess) > 0 {
			var next []resolve.NodeID
			for _, node := range toProcess {
				parents := parentEdges[node]
				gNode := gNodes[node]
				gNode.Version = g.Nodes[node].Version
				gNode.Distance = currDistance
				gNode.Parents = parents
				gNodes[node] = gNode

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

func (ds *DependencySubgraph) IsDevOnly(groups map[manifest.RequirementKey][]string) bool {
	if groups != nil {
		return !slices.ContainsFunc(ds.Nodes[0].Children, func(e resolve.Edge) bool {
			req := resolve.RequirementVersion{
				VersionKey: ds.Nodes[e.To].Version,
				Type:       e.Type.Clone(),
			}
			ecosystem, ok := util.OSVEcosystem[req.System]
			if !ok {
				return true
			}

			return !lockfile.Ecosystem(ecosystem).IsDevGroup(groups[manifest.MakeRequirementKey(req)])
		})
	}

	for _, e := range ds.Nodes[0].Children {
		if e.Type.HasAttr(dep.Dev) {
			continue
		}
		if e.To == ds.Dependency {
			return false
		}
		for _, e2 := range ds.Nodes[e.To].Children {
			if !e2.Type.HasAttr(dep.Dev) {
				return false
			}
		}
	}

	return true
}

func (ds *DependencySubgraph) ConstrainingSubgraph(ctx context.Context, cl resolve.Client, vuln *models.Vulnerability) *DependencySubgraph {
	end := ds.Nodes[ds.Dependency]
	newParents := make([]resolve.Edge, 0, len(end.Parents))
	for _, pEdge := range end.Parents {
		vk := end.Version
		vk.Version = pEdge.Requirement
		vk.VersionType = resolve.Requirement
		vers, err := cl.MatchingVersions(ctx, vk)
		if err != nil {
			newParents = append(newParents, pEdge)
			continue
		}
		bestVK := vers[len(vers)-1]

		if vulnUtil.IsAffected(*vuln, util.VKToPackageDetails(bestVK.VersionKey)) {
			newParents = append(newParents, pEdge)
		}
	}

	if len(newParents) == 0 {
		return ds
	}

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
