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

func TestResolve(t *testing.T) {
	t.Parallel()

	aliasType := func(knownAs string) dep.Type {
		t.Helper()
		typ := dep.NewType()
		typ.AddAttr(dep.KnownAs, knownAs)

		return typ
	}

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
			name:     "simple", // simple root -> dependency -> vuln
			version:  "1.0.0",
			system:   resolve.NPM,
			universe: "./fixtures/basic-universe.yaml",
			requirements: []requirement{
				{
					name:    "dependency",
					version: "^1.0.0",
					groups:  []string{"dev"},
				},
			},
		},
		{
			name:     "direct", // vulnerability in direct dependency
			version:  "1.0.0",
			system:   resolve.NPM,
			universe: "./fixtures/basic-universe.yaml",
			requirements: []requirement{
				{
					name:    "bad",
					version: "^2.0.0",
				},
			},
		},
		{
			name:     "duplicates", // same package with vulns included multiple times
			version:  "1.1.1",
			system:   resolve.NPM,
			universe: "./fixtures/basic-universe.yaml",
			requirements: []requirement{
				{
					name:    "bad",
					version: "^1.0.0",
					typ:     aliasType("bad-aliased"),
				},
				{
					name:    "dependency",
					version: "^2.0.0",
					groups:  []string{"dev"},
				},
				{
					name:    "dependency",
					version: "^1.0.0",
					typ:     aliasType("dependency-v1"),
				},
			},
		},
		{
			name:     "different-pkgs", // same vuln in two different packages
			version:  "3.0.0",
			system:   resolve.NPM,
			universe: "./fixtures/basic-universe.yaml",
			requirements: []requirement{
				{
					name:    "bad2",
					version: "^1.0.0",
				},
				{
					name:    "dependency",
					version: "^1.0.0",
				},
			},
		},
		{
			name:     "existing", // manifest package/version exists in universe already
			version:  "1.0.0",
			system:   resolve.NPM,
			universe: "./fixtures/basic-universe.yaml",
			requirements: []requirement{
				{
					name:    "dependency",
					version: "^2.0.0",
					typ:     dep.NewType(dep.Opt),
				},
			},
		},
		{
			name:     "non-problem", // non-problem chains
			version:  "1.0.0",
			system:   resolve.NPM,
			universe: "./fixtures/basic-universe.yaml",
			requirements: []requirement{
				{
					name:    "bad",
					version: "^1.0.0",
				},
				{
					name:    "dependency",
					version: "^3.0.0",
				},
			},
		},
		{
			name:     "diamond", // diamond dependency on vulnerable pkg
			version:  "1.0.0",
			system:   resolve.NPM,
			universe: "./fixtures/diamond-universe.yaml",
			requirements: []requirement{
				{
					name:    "pkg",
					version: "^1.0.0",
				},
				{
					name:    "dep-one",
					version: "^1.0.0",
					groups:  []string{"dev"},
				},
			},
		},
		{
			name:     "complex", // more complex graph/vulnerability structure
			version:  "9.9.9",
			system:   resolve.NPM,
			universe: "./fixtures/complex-universe.yaml",
			requirements: []requirement{
				{
					name:    "alice",
					version: "^1.0.0",
					typ:     aliasType("chuck"),
				},
				{
					name:    "bob",
					version: "2.2.2",
				},
				{
					name:    "dave",
					version: "~3.3.3",
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
			m.Groups = make(map[manifest.RequirementKey][]string)
			m.Requirements = make([]resolve.RequirementVersion, len(tt.requirements))
			for i, req := range tt.requirements {
				m.Requirements[i] = resolve.RequirementVersion{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							Name:   req.name,
							System: tt.system,
						},
						Version:     req.version,
						VersionType: resolve.Requirement,
					},
					Type: req.typ,
				}
				m.Groups[manifest.MakeRequirementKey(m.Requirements[i])] = req.groups
			}

			res, err := resolution.Resolve(context.Background(), cl, m)
			if err != nil {
				t.Fatalf("error resolving: %v", err)
			}
			checkResult(t, res)
		})
	}
}
