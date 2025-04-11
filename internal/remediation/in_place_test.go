package remediation_test

import (
	"cmp"
	"maps"
	"slices"
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/v2/internal/remediation"
	"github.com/google/osv-scanner/v2/internal/remediation/upgrade"
	"github.com/google/osv-scanner/v2/internal/resolution"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/google/osv-scanner/v2/internal/resolution/clienttest"
	"github.com/google/osv-scanner/v2/internal/resolution/depfile"
	"github.com/google/osv-scanner/v2/internal/resolution/lockfile"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func parseInPlaceFixture(t *testing.T, universePath, lockfilePath string) (*resolve.Graph, client.ResolutionClient) {
	t.Helper()

	rw, err := lockfile.GetReadWriter(lockfilePath)
	if err != nil {
		t.Fatalf("Failed to get ReadWriter: %v", err)
	}

	f, err := depfile.OpenLocalDepFile(lockfilePath)
	if err != nil {
		t.Fatalf("Failed to open lockfile: %v", err)
	}
	defer f.Close()

	g, err := rw.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse lockfile: %v", err)
	}

	return g, clienttest.NewMockResolutionClient(t, universePath)
}

func checkInPlaceResults(t *testing.T, res remediation.InPlaceResult) {
	// InPlaceResult is too large when dumped as JSON.
	// Extract & compare a subset of fields that are relevant for the tests.
	t.Helper()

	type minimalVuln struct {
		ID            string
		AffectedNodes []resolve.NodeID
	}

	toMinimalVuln := func(v resolution.Vulnerability) minimalVuln {
		t.Helper()
		nodes := make(map[resolve.NodeID]struct{})
		for _, sg := range v.Subgraphs {
			nodes[sg.Dependency] = struct{}{}
		}
		sortedNodes := slices.AppendSeq(make([]resolve.NodeID, 0, len(nodes)), maps.Keys(nodes))
		slices.Sort(sortedNodes)

		return minimalVuln{
			ID:            v.OSV.ID,
			AffectedNodes: sortedNodes,
		}
	}

	type minimalPatch struct {
		Patch    lockfile.DependencyPatch
		Resolved []minimalVuln
	}

	type minimalResult struct {
		Patches   []minimalPatch
		Unfixable []minimalVuln
	}

	minimalRes := minimalResult{
		Patches:   make([]minimalPatch, len(res.Patches)),
		Unfixable: make([]minimalVuln, len(res.Unfixable)),
	}

	for i, p := range res.Patches {
		minimalRes.Patches[i].Patch = p.DependencyPatch
		resolved := make([]minimalVuln, len(p.ResolvedVulns))
		for j, v := range p.ResolvedVulns {
			resolved[j] = toMinimalVuln(v)
		}
		minimalRes.Patches[i].Resolved = resolved
	}

	for i, v := range res.Unfixable {
		minimalRes.Unfixable[i] = toMinimalVuln(v)
	}

	// make sure the unfixable vulns are in a stable order
	slices.SortFunc(minimalRes.Unfixable, func(a, b minimalVuln) int {
		if c := cmp.Compare(a.ID, b.ID); c != 0 {
			return c
		}

		return slices.Compare(a.AffectedNodes, b.AffectedNodes)
	})

	testutility.NewSnapshot().MatchJSON(t, minimalRes)
}

func TestComputeInPlacePatches(t *testing.T) {
	t.Parallel()

	basicOpts := remediation.Options{
		DevDeps:       true,
		MaxDepth:      -1,
		UpgradeConfig: upgrade.NewConfig(),
	}

	tests := []struct {
		name         string
		universePath string
		lockfilePath string
		opts         remediation.Options
	}{
		{
			name:         "npm-santatracker",
			universePath: "./fixtures/santatracker/universe.yaml",
			lockfilePath: "./fixtures/santatracker/package-lock.json",
			opts:         basicOpts,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g, cl := parseInPlaceFixture(t, tt.universePath, tt.lockfilePath)
			res, err := remediation.ComputeInPlacePatches(t.Context(), cl, g, tt.opts)
			if err != nil {
				t.Fatalf("Failed to compute in-place patches: %v", err)
			}
			checkInPlaceResults(t, res)
		})
	}
}
