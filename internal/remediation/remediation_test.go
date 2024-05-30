package remediation_test

import (
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/pkg/models"
)

func TestMatchVuln(t *testing.T) {
	t.Parallel()
	var (
		// ID: VULN-001, Dev: false, Severity: 6.6, Depth: 3, Aliases: CVE-111, OSV-2
		vuln1 = resolution.ResolutionVuln{
			Vulnerability: models.Vulnerability{
				ID: "VULN-001",
				Severity: []models.Severity{
					{Type: models.SeverityCVSSV3, Score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H"}, // 6.6
					{Type: models.SeverityCVSSV2, Score: "AV:L/AC:L/Au:S/C:P/I:P/A:C"},                   // 5.7
				},
				Aliases: []string{"CVE-111", "OSV-2"},
			},
			DevOnly: false,
			ProblemChains: []resolution.DependencyChain{{
				Edges: []resolve.Edge{{From: 2, To: 3}, {From: 1, To: 2}, {From: 0, To: 1}},
			}},
		}
		// ID: VULN-002, Dev: true, Severity: N/A, Depth: 2
		vuln2 = resolution.ResolutionVuln{
			Vulnerability: models.Vulnerability{
				ID: "VULN-002",
				// No severity
			},
			DevOnly: true,
			ProblemChains: []resolution.DependencyChain{{
				Edges: []resolve.Edge{{From: 2, To: 3}, {From: 1, To: 2}, {From: 0, To: 1}},
			}},
			NonProblemChains: []resolution.DependencyChain{{
				Edges: []resolve.Edge{{From: 1, To: 3}, {From: 0, To: 1}},
			}},
		}
	)
	tests := []struct {
		name string
		vuln resolution.ResolutionVuln
		opt  remediation.RemediationOptions
		want bool
	}{
		{
			name: "basic match",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:  true,
				MaxDepth: -1,
			},
			want: true,
		},
		{
			name: "accept depth",
			vuln: vuln2,
			opt: remediation.RemediationOptions{
				DevDeps:  true,
				MaxDepth: 2,
			},
			want: true,
		},
		{
			name: "reject depth",
			vuln: vuln2,
			opt: remediation.RemediationOptions{
				DevDeps:  true,
				MaxDepth: 1,
			},
			want: false,
		},
		{
			name: "accept severity",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 6.6,
			},
			want: true,
		},
		{
			name: "reject severity",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 6.7,
			},
			want: false,
		},
		{
			name: "accept unknown severity",
			vuln: vuln2,
			opt: remediation.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 10.0,
			},
			want: true,
		},
		{
			name: "accept non-dev",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:  false,
				MaxDepth: -1,
			},
			want: true,
		},
		{
			name: "reject dev",
			vuln: vuln2,
			opt: remediation.RemediationOptions{
				DevDeps:  false,
				MaxDepth: -1,
			},
			want: false,
		},
		{
			name: "reject ID excluded",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				IgnoreVulns: []string{"VULN-001"},
			},
			want: false,
		},
		{
			name: "reject ID not in explicit",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:       true,
				MaxDepth:      -1,
				ExplicitVulns: []string{"VULN-999"},
			},
			want: false,
		},
		{
			name: "reject ID in explicit, but not matching other fields",
			vuln: vuln2,
			opt: remediation.RemediationOptions{
				DevDeps:       false,
				MaxDepth:      1,
				ExplicitVulns: []string{"VULN-002"},
			},
			want: false,
		},
		{
			name: "accept matching multiple 1",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:     false,
				MaxDepth:    3,
				MinSeverity: 5.0,
				IgnoreVulns: []string{"VULN-999"},
			},
			want: true,
		},
		{
			name: "accept matching multiple 2",
			vuln: vuln2,
			opt: remediation.RemediationOptions{
				DevDeps:       true,
				MaxDepth:      2,
				MinSeverity:   8.8,
				ExplicitVulns: []string{"VULN-002"},
			},
			want: true,
		},
		{
			name: "accept explicit ID in alias",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:       true,
				MaxDepth:      -1,
				ExplicitVulns: []string{"CVE-111"},
			},
			want: true,
		},
		{
			name: "reject excluded ID in alias",
			vuln: vuln1,
			opt: remediation.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				IgnoreVulns: []string{"OSV-2"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.opt.MatchVuln(tt.vuln); got != tt.want {
				t.Errorf("MatchVuln() = %v, want %v", got, tt.want)
			}
		})
	}
}
