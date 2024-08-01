package remediation_test

import (
	"cmp"
	"context"
	"slices"
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/clienttest"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/testutility"
	lf "github.com/google/osv-scanner/pkg/lockfile"
	"golang.org/x/exp/maps"
)

func parseRemediationFixture(t *testing.T, universePath, manifestPath string) (*resolution.ResolutionResult, client.ResolutionClient) {
	t.Helper()

	io, err := manifest.GetManifestIO(manifestPath)
	if err != nil {
		t.Fatalf("Failed to get ManifestIO: %v", err)
	}

	f, err := lf.OpenLocalDepFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to open manifest: %v", err)
	}
	defer f.Close()

	m, err := io.Read(f)
	if err != nil {
		t.Fatalf("Failed to parse manifest: %v", err)
	}

	cl := clienttest.NewMockResolutionClient(t, universePath)

	res, err := resolution.Resolve(context.Background(), cl, m)
	if err != nil {
		t.Fatalf("Failed to resolve manifest: %v", err)
	}

	return res, cl
}

func checkRemediationResults(t *testing.T, res []resolution.ResolutionDiff) {
	// ResolutionDiff is too large when dumped as JSON.
	// Extract & compare a subset of fields that are relevant for the tests.
	t.Helper()

	type minimalVuln struct {
		ID            string
		AffectedNodes []resolve.NodeID
	}

	toMinimalVuln := func(v resolution.ResolutionVuln) minimalVuln {
		t.Helper()
		nodes := make(map[resolve.NodeID]struct{})
		for _, c := range v.ProblemChains {
			nodes[c.Edges[0].To] = struct{}{}
		}
		for _, c := range v.NonProblemChains {
			nodes[c.Edges[0].To] = struct{}{}
		}
		sortedNodes := maps.Keys(nodes)
		slices.Sort(sortedNodes)

		return minimalVuln{
			ID:            v.Vulnerability.ID,
			AffectedNodes: sortedNodes,
		}
	}

	type minimalPatch struct {
		Deps              []manifest.DependencyPatch
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
