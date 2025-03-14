package tui

import (
	"fmt"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/v2/internal/resolution"
)

type chainGraphNode struct {
	vk         resolve.VersionKey
	isDirect   bool // if this is a direct dependency
	dependents []*chainGraphNode
	// in this representation, the dependents are the children of this node
	// so the root of the tree is rendered at the bottom
}

type ChainGraph struct {
	*chainGraphNode
}

func subgraphEdges(sg *resolution.DependencySubgraph, direct resolve.NodeID) []resolve.Edge {
	// find the shortest chain of edges from direct to the vulnerable node, excluding the root->direct edge.
	// return them in reverse order, with edges[0].To = sg.Dependency
	edges := make([]resolve.Edge, 0, sg.Nodes[0].Distance-1)
	nID := direct
	for nID != sg.Dependency {
		n := sg.Nodes[nID]
		idx := slices.IndexFunc(n.Children, func(e resolve.Edge) bool { return sg.Nodes[e.To].Distance == n.Distance-1 })
		if idx < 0 {
			break
		}
		edge := n.Children[idx]
		edges = append(edges, edge)
		nID = edge.To
	}
	slices.Reverse(edges)

	return edges
}

// FindChainGraphs constructs a graph of the shortest paths from each direct dependency to each unique vulnerable node
func FindChainGraphs(subgraphs []*resolution.DependencySubgraph) []ChainGraph {
	// Construct the ChainGraphs
	ret := make([]ChainGraph, 0, len(subgraphs))
	for _, sg := range subgraphs {
		nodes := make(map[resolve.NodeID]*chainGraphNode)
		isDirect := func(nID resolve.NodeID) bool {
			return slices.ContainsFunc(sg.Nodes[nID].Parents, func(e resolve.Edge) bool { return e.From == 0 })
		}
		// Create and add the vulnerable node to the returned graphs
		n := &chainGraphNode{
			vk:         sg.Nodes[sg.Dependency].Version,
			dependents: nil,
			isDirect:   isDirect(sg.Dependency),
		}
		ret = append(ret, ChainGraph{n})
		nodes[sg.Dependency] = n
		for _, startEdge := range sg.Nodes[0].Children {
			// Going up the chain, add the node to the previous' children if it's not there already
			for _, e := range subgraphEdges(sg, startEdge.To) {
				p := nodes[e.To]
				n, ok := nodes[e.From]
				if !ok {
					n = &chainGraphNode{
						vk:         sg.Nodes[e.From].Version,
						dependents: nil,
						isDirect:   isDirect(e.From),
					}
					nodes[e.From] = n
				}
				if !slices.Contains(p.dependents, n) {
					p.dependents = append(p.dependents, n)
				}
			}
		}
	}

	return ret
}

func (c ChainGraph) String() string {
	if c.chainGraphNode == nil {
		return ""
	}
	s, _ := c.subString(true)
	// Fill in the missing whitespace
	w := lipgloss.Width(s)
	h := lipgloss.Height(s)
	// need to use w+1 to force lipgloss to place whitespace
	return lipgloss.Place(w+1, h, lipgloss.Left, lipgloss.Top, s)
}

var (
	directNodeStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")).Margin(0, 1)                                  // blue text
	vulnNodeStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("1")).Padding(0, 1) // white on red background
	directVulnNodeStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("5")).Padding(0, 1) // white on purple background
)

// recursive construction of the visualized tree
// returns the subtree and the offset for where a child should connect to this
func (c *chainGraphNode) subString(isVuln bool) (string, int) {
	nodeStr := fmt.Sprintf("%s@%s", c.vk.Name, c.vk.Version)
	switch {
	case isVuln && c.isDirect:
		nodeStr = directVulnNodeStyle.Render(nodeStr)
	case isVuln:
		nodeStr = vulnNodeStyle.Render(nodeStr)
	case c.isDirect:
		nodeStr = directNodeStyle.Render(nodeStr)
	}
	nodeOffset := lipgloss.Width(nodeStr) / 2

	// No children, just show the text
	if len(c.dependents) == 0 {
		return nodeStr, nodeOffset
	}

	// one child, add a single line connecting this to the child above it
	if len(c.dependents) == 1 {
		childStr, childCenter := c.dependents[0].subString(false)
		if nodeOffset > childCenter {
			// left-pad the child if the parent is wider
			childStr = lipgloss.JoinHorizontal(lipgloss.Bottom, strings.Repeat(" ", nodeOffset-childCenter), childStr)
			childCenter = nodeOffset
		}
		nodeStr = strings.Repeat(" ", childCenter-nodeOffset) + nodeStr
		joinerStr := strings.Repeat(" ", childCenter) + "│"

		return fmt.Sprintf("%s\n%s\n%s", childStr, joinerStr, nodeStr), childCenter
	}

	// multiple children:
	// Join the children together on one line
	nChilds := len(c.dependents)
	paddedChildStrings := make([]string, 0, 2*nChilds) // string of children, with padding strings in between
	childOffsets := make([]int, 0, nChilds)            // where above the children to connect the lines to them
	width := 0
	for _, ch := range c.dependents {
		str, off := ch.subString(false)
		paddedChildStrings = append(paddedChildStrings, str, " ")
		childOffsets = append(childOffsets, width+off)
		width += lipgloss.Width(str) + 1
	}
	joinedChildren := lipgloss.JoinHorizontal(lipgloss.Bottom, paddedChildStrings...)

	// create the connecting line
	// connector bits: ┌ ─ ┼ ┐ ┬ ┴ ┘ └
	firstOffset := childOffsets[0]
	lastOffset := childOffsets[nChilds-1]
	var midOffset int // where on the line to connect the parent
	if nChilds%2 == 0 {
		// if there's an even number of children, connect between the middle two
		midOffset = (childOffsets[nChilds/2-1] + childOffsets[nChilds/2]) / 2
	} else {
		// otherwise, connect inline with the middle child
		midOffset = childOffsets[nChilds/2]
	}

	line := make([]rune, lastOffset+1)
	offsetIdx := 0
	for i := range line {
		switch {
		case i < firstOffset:
			line[i] = ' '
		case i == firstOffset:
			line[i] = '└'
			offsetIdx++
		case i == lastOffset:
			line[i] = '┘'
			offsetIdx++
		case i == midOffset:
			if i == childOffsets[offsetIdx] {
				line[i] = '┼'
				offsetIdx++
			} else {
				line[i] = '┬'
			}
		case i == childOffsets[offsetIdx]:
			line[i] = '┴'
			offsetIdx++
		default:
			line[i] = '─'
		}
	}

	// join everything together
	linedChildren := fmt.Sprintf("%s\n%s", joinedChildren, string(line))
	if nodeOffset > midOffset {
		// left-pad the children if the parent is wider
		linedChildren = lipgloss.JoinHorizontal(lipgloss.Bottom, strings.Repeat(" ", nodeOffset-midOffset), linedChildren)
		midOffset = nodeOffset
	}

	nodeStr = strings.Repeat(" ", midOffset-nodeOffset) + nodeStr

	return fmt.Sprintf("%s\n%s", linedChildren, nodeStr), midOffset
}
