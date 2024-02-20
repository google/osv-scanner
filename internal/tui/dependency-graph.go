package tui

import (
	"fmt"
	"strings"

	"deps.dev/util/resolve"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/internal/resolution"
	"golang.org/x/exp/slices"
)

type chainGraphNode struct {
	vk       resolve.VersionKey
	isDirect bool // if this is a direct dependency
	children []*chainGraphNode
	// in this representation, a child is something that depends on this node
	// so the root of the tree is rendered at the bottom
}

type ChainGraph struct {
	*chainGraphNode
}

// for each unique vulnerable node, construct the graph from that node to each connected direct dependency,
// choosing only the shortest path
func FindChainGraphs(chains []resolution.DependencyChain) []ChainGraph {
	// TODO: this is not deterministic

	// identifier for unique direct dep causes of unique vulnerabilities,
	// used as a map key, so needs to be comparable
	type chainEndpoints struct {
		vulnDep   resolve.NodeID
		directDep resolve.NodeID
	}

	// Find the shortest-length dependency chain for each direct/vulnerable node pair
	shortestChains := make(map[chainEndpoints]resolution.DependencyChain)
	for _, c := range chains {
		endpoints := chainEndpoints{c.Edges[0].To, c.Edges[len(c.Edges)-1].To}
		old, ok := shortestChains[endpoints]
		if !ok {
			shortestChains[endpoints] = c
			continue
		}
		if len(old.Edges) > len(c.Edges) {
			shortestChains[endpoints] = c
		}
	}

	// Construct the ChainGraphs
	nodes := make(map[resolve.NodeID]*chainGraphNode)
	var ret []ChainGraph
	for _, c := range shortestChains {
		if _, ok := nodes[c.Edges[0].To]; !ok {
			// haven't encountered this specific vulnerable node before
			// create it and add it to the returned graphs
			vk, _ := c.End()
			n := &chainGraphNode{
				vk:       vk,
				children: nil,
				isDirect: c.Edges[0].From == 0,
			}
			ret = append(ret, ChainGraph{n})
			nodes[c.Edges[0].To] = n
		}
		// Going up the chain, add the node to the previous' children if it's not there already
		for i, e := range c.Edges[:len(c.Edges)-1] {
			p := nodes[e.To]
			n, ok := nodes[e.From]
			if !ok {
				vk, _ := c.At(i + 1)
				n = &chainGraphNode{
					vk:       vk,
					children: nil,
					isDirect: i == len(c.Edges)-2,
				}
				nodes[e.From] = n
			}
			if !slices.Contains(p.children, n) {
				p.children = append(p.children, n)
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
	if len(c.children) == 0 {
		return nodeStr, nodeOffset
	}

	// one child, add a single line connecting this to the child above it
	if len(c.children) == 1 {
		childStr, childCenter := c.children[0].subString(false)
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
	nChilds := len(c.children)
	paddedChildStrings := make([]string, 0, 2*nChilds) // string of children, with padding strings in between
	childOffsets := make([]int, 0, nChilds)            // where above the children to connect the lines to them
	width := 0
	for _, ch := range c.children {
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
