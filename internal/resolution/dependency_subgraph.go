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
	Graph      *resolve.Graph
	Dependency resolve.NodeID
	Edges      map[resolve.NodeID]GraphNode
}

func (ds DependencySubgraph) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[%d: %s]\n", ds.Dependency, ds.Edges[ds.Dependency].Version)
	for nID, e := range ds.Edges {
		for _, p := range e.Parents {
			fmt.Fprintf(&sb, "%d@%s ", p.From, p.Requirement)
		}
		fmt.Fprintf(&sb, "-> %d: %s (%d) ->", nID, e.Version, e.Distance)
		for _, c := range e.Children {
			fmt.Fprintf(&sb, " %d@%s", c.To, c.Requirement)
		}
		fmt.Fprintln(&sb)
	}

	return sb.String()
}

func ComputeSubgraphs(g *resolve.Graph, nodes []resolve.NodeID) []DependencySubgraph {
	// find the parent nodes of each node in graph, for easier traversal
	parentEdges := make(map[resolve.NodeID][]resolve.Edge)
	for _, e := range g.Edges {
		// check for a self-dependency, just in case
		if e.From == e.To {
			continue
		}
		parentEdges[e.To] = append(parentEdges[e.To], e)
	}

	subGraphs := make([]DependencySubgraph, 0, len(nodes))
	for _, node := range nodes {
		gEdges := make(map[resolve.NodeID]GraphNode)

		seenNodes := make(map[resolve.NodeID]struct{})
		seenNodes[node] = struct{}{}
		toProcess := []resolve.NodeID{node}
		for len(toProcess) > 0 {
			node := toProcess[len(toProcess)-1]
			toProcess = toProcess[:len(toProcess)-1]

			parents := parentEdges[node]
			gNode := gEdges[node]
			gNode.Version = g.Nodes[node].Version
			gNode.Parents = parents
			gEdges[node] = gNode

			for _, edge := range parents {
				nID := edge.From
				pNode := gEdges[nID]
				pNode.Children = append(pNode.Children, edge)
				if pNode.Distance == 0 || pNode.Distance > gNode.Distance+1 {
					pNode.Distance = gNode.Distance + 1
				}
				gEdges[nID] = pNode
				if _, ok := seenNodes[nID]; !ok {
					toProcess = append(toProcess, nID)
					seenNodes[nID] = struct{}{}
				}
			}
		}

		subGraphs = append(subGraphs, DependencySubgraph{
			Graph:      g,
			Dependency: node,
			Edges:      gEdges,
		})
	}

	return subGraphs
}

func (ds DependencySubgraph) IsDevOnly(groups map[manifest.RequirementKey][]string) bool {
	if groups != nil {
		return !slices.ContainsFunc(ds.Edges[0].Children, func(e resolve.Edge) bool {
			req := resolve.RequirementVersion{
				VersionKey: ds.Graph.Nodes[e.To].Version,
				Type:       e.Type.Clone(),
			}
			ecosystem, ok := util.OSVEcosystem[req.System]
			if !ok {
				return true
			}

			return !lockfile.Ecosystem(ecosystem).IsDevGroup(groups[manifest.MakeRequirementKey(req)])
		})
	}

	for _, e := range ds.Edges[0].Children {
		if e.Type.HasAttr(dep.Dev) {
			continue
		}
		if e.To == ds.Dependency {
			return false
		}
		for _, e2 := range ds.Edges[e.To].Children {
			if !e2.Type.HasAttr(dep.Dev) {
				return false
			}
		}
	}

	return true
}

func (ds DependencySubgraph) ConstrainingSubgraph(ctx context.Context, cl resolve.Client, vuln *models.Vulnerability) DependencySubgraph {
	end := ds.Edges[ds.Dependency]
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
		return DependencySubgraph{
			Graph:      ds.Graph,
			Dependency: ds.Dependency,
			Edges:      nil,
		}
	}

	newEdges := make(map[resolve.NodeID]GraphNode)
	newEdges[ds.Dependency] = GraphNode{
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
			oldEdge := ds.Edges[nID]
			newEdges[nID] = GraphNode{
				Version:  oldEdge.Version,
				Distance: currDistance,
				Parents:  slices.Clone(oldEdge.Parents),
				Children: slices.Clone(oldEdge.Children),
			}
			for _, e := range oldEdge.Parents {
				if _, ok := seen[e.From]; !ok {
					seen[e.From] = struct{}{}
					next = append(next, e.From)
				}
			}
		}
		toProcess = next
		currDistance++
	}
	for nID, edge := range newEdges {
		edge.Children = slices.DeleteFunc(edge.Children, func(e resolve.Edge) bool {
			_, ok := seen[e.To]
			return !ok
		})
		newEdges[nID] = edge
	}

	return DependencySubgraph{
		Graph:      ds.Graph,
		Dependency: ds.Dependency,
		Edges:      newEdges,
	}
}
