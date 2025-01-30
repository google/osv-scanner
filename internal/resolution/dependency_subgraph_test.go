package resolution_test

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/schema"
	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/resolution"
	"github.com/google/osv-scanner/v2/internal/resolution/manifest"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestDependencySubgraph(t *testing.T) {
	t.Parallel()
	g, err := schema.ParseResolve(`
a 0.0.1
	b@^1.0.1 1.0.1
		$c@^1.0.0
		d: d@^2.2.2 2.2.2
	c: c@^1.0.2 1.0.2
		e@1.0.0 1.0.0
			$d@^2.0.0
	f@^1.1.1 1.1.1
		$c@^1.0.1
		g@^2.2.2 2.2.2
			h@^3.3.3 3.3.3
				$d@^2.2.0
`, resolve.NPM)
	if err != nil {
		t.Fatalf("failed to parse test graph: %v", err)
	}

	nodes := make([]resolve.NodeID, len(g.Nodes)-1)
	for i := range nodes {
		nodes[i] = resolve.NodeID(i + 1)
	}

	subgraphs := resolution.ComputeSubgraphs(g, nodes)
	for _, sg := range subgraphs {
		checkSubgraphVersions(t, sg, g)
		checkSubgraphEdges(t, sg)
		checkSubgraphNodesReachable(t, sg)
		checkSubgraphDistances(t, sg)
	}
}

func TestConstrainingSubgraph(t *testing.T) {
	t.Parallel()
	const vulnPkgName = "vuln"
	g, err := schema.ParseResolve(`
root 1.0.0
	vuln: vuln@<3 1.0.1
	nonprob1@^1.0.0 1.0.0
		$vuln@>1
	prob1@^1.0.0 1.0.0
		$vuln@^1.0.0
	prob2@^2.0.0 2.0.0
		nonprob2@* 1.0.0
			$vuln@*
		$vuln@*
		dep@3.0.0 3.0.0
			$vuln@1.0.1
`, resolve.NPM)
	if err != nil {
		t.Fatalf("failed to parse test graph: %v", err)
	}

	nID := slices.IndexFunc(g.Nodes, func(n resolve.Node) bool { return n.Version.Name == vulnPkgName })
	if nID < 0 {
		t.Fatalf("failed to find vulnerable node in test graph")
	}
	subgraph := resolution.ComputeSubgraphs(g, []resolve.NodeID{resolve.NodeID(nID)})[0]

	cl := resolve.NewLocalClient()
	v := resolve.Version{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.NPM,
				Name:   vulnPkgName,
			},
			VersionType: resolve.Concrete,
		},
	}
	v.Version = "1.0.0"
	cl.AddVersion(v, []resolve.RequirementVersion{})
	v.Version = "1.0.1"
	cl.AddVersion(v, []resolve.RequirementVersion{})
	v.Version = "2.0.0"
	cl.AddVersion(v, []resolve.RequirementVersion{})
	vuln := &models.Vulnerability{
		ID: "VULN-001",
		Affected: []models.Affected{{
			Package: models.Package{
				Ecosystem: "npm",
				Name:      vulnPkgName,
			},
			Ranges: []models.Range{
				{
					Type:   "SEMVER",
					Events: []models.Event{{Introduced: "0"}, {Fixed: "2.0.0"}},
				},
			},
		},
		}}
	got := subgraph.ConstrainingSubgraph(context.Background(), cl, vuln)
	checkSubgraphVersions(t, got, g)
	checkSubgraphEdges(t, got)
	checkSubgraphNodesReachable(t, got)
	checkSubgraphDistances(t, got)

	// Checking that we have the expected remaining nodes
	expectedRemoved := []string{"nonprob1", "nonprob2"}
	for _, pkgName := range expectedRemoved {
		nID := slices.IndexFunc(g.Nodes, func(n resolve.Node) bool { return n.Version.Name == pkgName })
		if nID < 0 {
			t.Fatalf("failed to find expected node in test graph")
		}
		if _, found := got.Nodes[resolve.NodeID(nID)]; found {
			t.Errorf("non-constraining node was not removed from constraining subgraph: %s", pkgName)
		}
	}
	if len(got.Nodes) != len(subgraph.Nodes)-len(expectedRemoved) {
		t.Errorf("extraneous nodes found in constraining subgraph")
	}
	for nID := range got.Nodes {
		if _, ok := subgraph.Nodes[nID]; !ok {
			t.Errorf("extraneous node (%v) found in constraining subgraph", nID)
		}
	}

	// Check that ConstrainingSubgraph is stable if reapplied
	again := got.ConstrainingSubgraph(context.Background(), cl, vuln)
	if diff := gocmp.Diff(got, again); diff != "" {
		t.Errorf("ConstrainingSubgraph output changed on reapply (-want +got):\n%s", diff)
	}
}

func TestSubgraphIsDevOnly(t *testing.T) {
	t.Parallel()
	g, err := schema.ParseResolve(`
a 1.0.0
	b@1.0.0 1.0.0
		prod: prod@1.0.0 1.0.0
	Dev|c@1.0.0 1.0.0
		$prod@1.0.0
		dev: dev@1.0.0 1.0.0
	Dev|d@1.0.0 1.0.0
		$dev@1.0.0
`, resolve.NPM)
	if err != nil {
		t.Fatalf("failed to parse test graph: %v", err)
	}

	prodID := slices.IndexFunc(g.Nodes, func(n resolve.Node) bool { return n.Version.Name == "prod" })
	if prodID < 0 {
		t.Fatalf("failed to find vulnerable node in test graph")
	}
	devID := slices.IndexFunc(g.Nodes, func(n resolve.Node) bool { return n.Version.Name == "dev" })
	if devID < 0 {
		t.Fatalf("failed to find vulnerable node in test graph")
	}

	subgraphs := resolution.ComputeSubgraphs(g, []resolve.NodeID{resolve.NodeID(prodID), resolve.NodeID(devID)})
	prodGraph := subgraphs[0]
	devGraph := subgraphs[1]

	if prodGraph.IsDevOnly(nil) {
		t.Errorf("non-dev subgraph has IsDevOnly(nil) == true")
	}
	if !devGraph.IsDevOnly(nil) {
		t.Errorf("dev-only subgraph has IsDevOnly(nil) == false")
	}

	groups := map[manifest.RequirementKey][]string{
		{PackageKey: resolve.PackageKey{System: resolve.NPM, Name: "c"}, EcosystemSpecific: ""}: {"dev"},
		{PackageKey: resolve.PackageKey{System: resolve.NPM, Name: "d"}, EcosystemSpecific: ""}: {"dev"},
	}
	if prodGraph.IsDevOnly(groups) {
		t.Errorf("non-dev subgraph has IsDevOnly(groups) == true")
	}
	if !devGraph.IsDevOnly(groups) {
		t.Errorf("dev-only subgraph has IsDevOnly(groups) == false")
	}
}

func checkSubgraphVersions(t *testing.T, sg *resolution.DependencySubgraph, g *resolve.Graph) {
	// Check that the nodes and versions in the subgraph are correct
	t.Helper()
	if _, ok := sg.Nodes[0]; !ok {
		t.Errorf("DependencySubgraph missing root node (0)")
	}
	if _, ok := sg.Nodes[sg.Dependency]; !ok {
		t.Errorf("DependencySubgraph missing Dependency node (%v)", sg.Dependency)
	}
	for nID, node := range sg.Nodes {
		if nID < 0 || int(nID) >= len(g.Nodes) {
			t.Errorf("DependencySubgraph contains invalid node ID: %v", nID)
			continue
		}
		want := g.Nodes[nID].Version
		got := node.Version
		if diff := gocmp.Diff(want, got); diff != "" {
			t.Errorf("DependencySubgraph node %v does not match Graph (-want +got):\n%s", nID, diff)
		}
	}
}

func checkSubgraphEdges(t *testing.T, sg *resolution.DependencySubgraph) {
	// Check that every edge in a node's Parents appears in that parent's Children and vice versa.
	t.Helper()
	// Check the root node has no parents & end node has no children
	if root, ok := sg.Nodes[0]; !ok {
		t.Errorf("DependencySubgraph missing root node (0)")
	} else if len(root.Parents) != 0 {
		t.Errorf("DependencySubgraph root node (0) has parent nodes: %v", root.Parents)
	}
	if end, ok := sg.Nodes[sg.Dependency]; !ok {
		t.Errorf("DependencySubgraph missing Dependency node (%v)", sg.Dependency)
	} else if len(end.Children) != 0 {
		t.Errorf("DependencySubgraph Dependency node (%v) has child nodes: %v", sg.Dependency, end.Children)
	}

	edgeEq := func(a, b resolve.Edge) bool {
		return a.From == b.From &&
			a.To == b.To &&
			a.Requirement == b.Requirement &&
			a.Type.Compare(b.Type) == 0
	}

	// Check each node's parents/children for same edges
	for nID, node := range sg.Nodes {
		// Only the root node should have no parents
		if len(node.Parents) == 0 && nID != 0 {
			t.Errorf("DependencySubgraph node %v has no parent nodes", nID)
		}
		for _, e := range node.Parents {
			if e.To != nID {
				t.Errorf("DependencySubgraph node %v contains invalid parent edge: %v", nID, e)
				continue
			}
			parent, ok := sg.Nodes[e.From]
			if !ok {
				t.Errorf("DependencySubgraph edge missing node in subgraph: %v", e)
			}
			if !slices.ContainsFunc(parent.Children, func(edge resolve.Edge) bool { return edgeEq(e, edge) }) {
				t.Errorf("DependencySubgraph node %v missing child edge: %v", e.From, e)
			}
		}

		// Only the end node should have no children
		if len(node.Children) == 0 && nID != sg.Dependency {
			t.Errorf("DependencySubgraph node %v has no child nodes", nID)
		}
		for _, e := range node.Children {
			if e.From != nID {
				t.Errorf("DependencySubgraph node %v contains invalid child edge: %v", nID, e)
				continue
			}
			child, ok := sg.Nodes[e.To]
			if !ok {
				t.Errorf("DependencySubgraph edge missing node in subgraph: %v", e)
			}
			if !slices.ContainsFunc(child.Parents, func(edge resolve.Edge) bool { return edgeEq(e, edge) }) {
				t.Errorf("DependencySubgraph node %v missing parent edge: %v", e.To, e)
			}
		}
	}
}

func checkSubgraphNodesReachable(t *testing.T, sg *resolution.DependencySubgraph) {
	// Check that every node in the subgraph is reachable from the root node.
	t.Helper()
	seen := make(map[resolve.NodeID]struct{})
	todo := make([]resolve.NodeID, 0, len(sg.Nodes))
	todo = append(todo, 0)
	seen[0] = struct{}{}
	for len(todo) > 0 {
		nID := todo[0]
		todo = todo[1:]
		node, ok := sg.Nodes[nID]
		if !ok {
			t.Errorf("DependencySubgraph missing expected node %v", nID)
			continue
		}
		for _, e := range node.Children {
			if _, ok := seen[e.To]; !ok {
				todo = append(todo, e.To)
				seen[e.To] = struct{}{}
			}
		}
	}

	got := slices.Sorted(maps.Keys(seen))
	want := slices.Sorted(maps.Keys(sg.Nodes))
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("DependencySubgraph reachable nodes mismatch (-want +got):\n%s", diff)
	}
}

func checkSubgraphDistances(t *testing.T, sg *resolution.DependencySubgraph) {
	// Check that the distances of each node have the correct value.
	t.Helper()
	if end, ok := sg.Nodes[sg.Dependency]; !ok {
		t.Errorf("DependencySubgraph missing Dependency node (%v)", sg.Dependency)
	} else if end.Distance != 0 {
		t.Errorf("DependencySubgraph end Dependency distance is not 0")
	}

	// Each node's distance should be one more than its smallest child's distance.
	for nID, node := range sg.Nodes {
		// The end dependency should have a distance of 0
		if nID == sg.Dependency {
			if node.Distance != 0 {
				t.Errorf("DependencySubgraph Dependency node (%v) has nonzero distance: %d", nID, node.Distance)
			}

			continue
		}

		if len(node.Children) == 0 {
			t.Errorf("DependencySubgraph node %v has no child nodes", nID)
			continue
		}
		e := slices.MinFunc(node.Children, func(a, b resolve.Edge) int { return cmp.Compare(sg.Nodes[a.To].Distance, sg.Nodes[b.To].Distance) })
		want := sg.Nodes[e.To].Distance + 1
		if node.Distance != want {
			t.Errorf("DependencySubgraph node %v Distance = %d, want = %d", nID, node.Distance, want)
		}
	}
}
