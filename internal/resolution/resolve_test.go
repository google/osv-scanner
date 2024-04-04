package resolution_test

import (
	"cmp"
	"context"
	"slices"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/clienttest"
	"github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/testutility"
)

func checkResult(t *testing.T, result *resolution.ResolutionResult) {
	t.Helper()
	snap := testutility.NewSnapshot()
	snap.MatchText(t, result.Graph.String())

	type minimalVuln struct {
		ID               string
		DevOnly          bool
		ProblemChains    [][]resolve.Edge
		NonProblemChains [][]resolve.Edge
	}

	minVulns := make([]minimalVuln, len(result.Vulns))
	for i, v := range result.Vulns {
		minVulns[i] = minimalVuln{
			ID:               v.Vulnerability.ID,
			DevOnly:          v.DevOnly,
			ProblemChains:    make([][]resolve.Edge, len(v.ProblemChains)),
			NonProblemChains: make([][]resolve.Edge, len(v.NonProblemChains)),
		}
		for j, c := range v.ProblemChains {
			minVulns[i].ProblemChains[j] = c.Edges
		}
		for j, c := range v.NonProblemChains {
			minVulns[i].NonProblemChains[j] = c.Edges
		}
	}
	slices.SortFunc(minVulns, func(a, b minimalVuln) int {
		return cmp.Compare(a.ID, b.ID)
	})
	snap.MatchJSON(t, minVulns)
}

func aliasType(knownAs string) dep.Type {
	typ := dep.NewType()
	typ.AddAttr(dep.KnownAs, knownAs)
	return typ
}

func TestResolve(t *testing.T) {
	type requirement struct {
		name    string
		version string
		typ     dep.Type
		groups  []string
	}
	tests := []struct {
		name         string
		version      string
		system       resolve.System
		universe     string
		requirements []requirement
	}{
		{
			name:     "test",
			version:  "1.0.0",
			system:   resolve.NPM,
			universe: "./fixtures/universe.yaml",
			requirements: []requirement{
				{
					name:    "bob",
					version: "^1.0.0",
				},
				{
					name:    "charlie",
					version: "2.0.1",
				},
				{
					name:    "charlie",
					version: "2.0.0",
					typ:     aliasType("sharlie"),
				},
				{
					name:    "alice",
					version: "1.0.0",
					typ:     aliasType("zalice"),
				},
				{
					name:    "alice",
					version: "^1.2.3",
					groups:  []string{"dev"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cl := clienttest.NewMockResolutionClient(t, tt.universe)
			var m manifest.Manifest
			m.Root = resolve.Version{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						Name:   tt.name,
						System: tt.system,
					},
					Version:     tt.version,
					VersionType: resolve.Concrete,
				},
			}
			m.Groups = make(map[resolve.PackageKey][]string)
			m.Requirements = make([]resolve.RequirementVersion, len(tt.requirements))
			for i, req := range tt.requirements {
				pk := resolve.PackageKey{
					Name:   req.name,
					System: tt.system,
				}
				m.Requirements[i] = resolve.RequirementVersion{
					VersionKey: resolve.VersionKey{
						PackageKey:  pk,
						Version:     req.version,
						VersionType: resolve.Requirement,
					},
					Type: req.typ,
				}
				m.Groups[pk] = req.groups
			}

			res, err := resolution.Resolve(context.Background(), cl, m)
			if err != nil {
				t.Fatalf("error resolving: %v", err)
			}
			checkResult(t, res)
		})
	}
	t.Fail()
}
