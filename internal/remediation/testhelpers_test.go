package remediation_test

import (
	"cmp"
	"maps"
	"slices"
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/v2/internal/resolution"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/google/osv-scanner/v2/internal/resolution/clienttest"
	"github.com/google/osv-scanner/v2/internal/resolution/depfile"
	"github.com/google/osv-scanner/v2/internal/resolution/manifest"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func parseRemediationFixture(t *testing.T, universePath, vulnPath, manifestPath string, opts resolution.ResolveOpts) (*resolution.Result, client.ResolutionClient) {
	t.Helper()

	rw, err := manifest.GetReadWriter(manifestPath, "")
	if err != nil {
		t.Fatalf("Failed to get ReadWriter: %v", err)
	}

	f, err := depfile.OpenLocalDepFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to open manifest: %v", err)
	}
	defer f.Close()

	m, err := rw.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse manifest: %v", err)
	}

	cl := clienttest.NewMockResolutionClient(t, universePath, vulnPath)

	res, err := resolution.Resolve(t.Context(), cl, m, opts)
	if err != nil {
		t.Fatalf("Failed to resolve manifest: %v", err)
	}

	return res, cl
}

func checkRemediationResults(t *testing.T, res []resolution.Difference) {
	// ResolutionDiff is too large when dumped as JSON.
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
			ID:            v.OSV.GetId(),
			AffectedNodes: sortedNodes,
		}
	}

	type minimalPatch struct {
		Deps              []manifest.DependencyPatch // TODO: The dep.Type does not marshal to JSON.
		EcosystemSpecific any
	}

	type minimalDiff struct {
		Patch        minimalPatch
		RemovedVulns []minimalVuln
		AddedVulns   []minimalVuln
	}

	minimalRes := make([]minimalDiff, len(res))
	for i, diff := range res {
		minimalRes[i].Patch = minimalPatch{
			Deps:              diff.Deps,
			EcosystemSpecific: diff.EcosystemSpecific,
		}
		minimalRes[i].AddedVulns = make([]minimalVuln, len(diff.AddedVulns))
		for j, v := range diff.AddedVulns {
			minimalRes[i].AddedVulns[j] = toMinimalVuln(v)
		}
		minimalRes[i].RemovedVulns = make([]minimalVuln, len(diff.RemovedVulns))
		for j, v := range diff.RemovedVulns {
			minimalRes[i].RemovedVulns[j] = toMinimalVuln(v)
		}
		cmpFn := func(a, b minimalVuln) int {
			if c := cmp.Compare(a.ID, b.ID); c != 0 {
				return c
			}

			return slices.Compare(a.AffectedNodes, b.AffectedNodes)
		}
		slices.SortFunc(minimalRes[i].AddedVulns, cmpFn)
		slices.SortFunc(minimalRes[i].RemovedVulns, cmpFn)
	}

	testutility.NewSnapshot().MatchJSON(t, minimalRes)
}
