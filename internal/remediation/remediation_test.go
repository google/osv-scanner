package remediation_test

import (
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/v2/internal/remediation"
	"github.com/google/osv-scanner/v2/internal/resolution"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestMatchVuln(t *testing.T) {
	t.Parallel()
	var (
		// ID: VULN-001, Dev: false, Severity: 6.6, Depth: 3, Aliases: CVE-111, OSV-2
		vuln1 = resolution.Vulnerability{
			OSV: &osvschema.Vulnerability{
				Id: "VULN-001",
				Severity: []*osvschema.Severity{
					{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H"}, // 6.6
					{Type: osvschema.Severity_CVSS_V2, Score: "AV:L/AC:L/Au:S/C:P/I:P/A:C"},                   // 5.7
				},
				Aliases: []string{"CVE-111", "OSV-2"},
			},
			DevOnly: false,
			Subgraphs: []*resolution.DependencySubgraph{{
				Dependency: 3,
				Nodes: map[resolve.NodeID]resolution.GraphNode{
					3: {
						Distance: 0,
						Parents:  []resolve.Edge{{From: 2, To: 3}},
						Children: []resolve.Edge{},
					},
					2: {
						Distance: 1,
						Parents:  []resolve.Edge{{From: 1, To: 2}},
						Children: []resolve.Edge{{From: 2, To: 3}},
					},
					1: {
						Distance: 2,
						Parents:  []resolve.Edge{{From: 0, To: 1}},
						Children: []resolve.Edge{{From: 1, To: 2}},
					},
					0: {
						Distance: 3,
						Parents:  []resolve.Edge{},
						Children: []resolve.Edge{{From: 0, To: 1}},
					},
				},
			}},
		}
		// ID: VULN-002, Dev: true, Severity: N/A, Depth: 2
		vuln2 = resolution.Vulnerability{
			OSV: &osvschema.Vulnerability{
				Id: "VULN-002",
				// No severity
			},
			DevOnly: true,
			Subgraphs: []*resolution.DependencySubgraph{{
				Dependency: 3,
				Nodes: map[resolve.NodeID]resolution.GraphNode{
					3: {
						Distance: 0,
						Parents:  []resolve.Edge{{From: 2, To: 3}, {From: 1, To: 3}},
						Children: []resolve.Edge{},
					},
					2: {
						Distance: 1,
						Parents:  []resolve.Edge{{From: 1, To: 2}},
						Children: []resolve.Edge{{From: 2, To: 3}},
					},
					1: {
						Distance: 1,
						Parents:  []resolve.Edge{{From: 0, To: 1}},
						Children: []resolve.Edge{{From: 1, To: 2}, {From: 1, To: 3}},
					},
					0: {
						Distance: 2,
						Parents:  []resolve.Edge{},
						Children: []resolve.Edge{{From: 0, To: 1}},
					},
				},
			}},
		}
	)
	tests := []struct {
		name string
		vuln resolution.Vulnerability
		opt  remediation.Options
		want bool
	}{
		{
			name: "basic_match",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:  true,
				MaxDepth: -1,
			},
			want: true,
		},
		{
			name: "accept_depth",
			vuln: vuln2,
			opt: remediation.Options{
				DevDeps:  true,
				MaxDepth: 2,
			},
			want: true,
		},
		{
			name: "reject_depth",
			vuln: vuln2,
			opt: remediation.Options{
				DevDeps:  true,
				MaxDepth: 1,
			},
			want: false,
		},
		{
			name: "accept_severity",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 6.6,
			},
			want: true,
		},
		{
			name: "reject_severity",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 6.7,
			},
			want: false,
		},
		{
			name: "accept_unknown_severity",
			vuln: vuln2,
			opt: remediation.Options{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 10.0,
			},
			want: true,
		},
		{
			name: "accept_non-dev",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:  false,
				MaxDepth: -1,
			},
			want: true,
		},
		{
			name: "reject_dev",
			vuln: vuln2,
			opt: remediation.Options{
				DevDeps:  false,
				MaxDepth: -1,
			},
			want: false,
		},
		{
			name: "reject_ID_excluded",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:     true,
				MaxDepth:    -1,
				IgnoreVulns: []string{"VULN-001"},
			},
			want: false,
		},
		{
			name: "reject_ID_not_in_explicit",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:       true,
				MaxDepth:      -1,
				ExplicitVulns: []string{"VULN-999"},
			},
			want: false,
		},
		{
			name: "reject_ID_in_explicit,_but_not_matching_other_fields",
			vuln: vuln2,
			opt: remediation.Options{
				DevDeps:       false,
				MaxDepth:      1,
				ExplicitVulns: []string{"VULN-002"},
			},
			want: false,
		},
		{
			name: "accept_matching_multiple_1",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:     false,
				MaxDepth:    3,
				MinSeverity: 5.0,
				IgnoreVulns: []string{"VULN-999"},
			},
			want: true,
		},
		{
			name: "accept_matching_multiple_2",
			vuln: vuln2,
			opt: remediation.Options{
				DevDeps:       true,
				MaxDepth:      2,
				MinSeverity:   8.8,
				ExplicitVulns: []string{"VULN-002"},
			},
			want: true,
		},
		{
			name: "accept_explicit_ID_in_alias",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:       true,
				MaxDepth:      -1,
				ExplicitVulns: []string{"CVE-111"},
			},
			want: true,
		},
		{
			name: "reject_excluded_ID_in_alias",
			vuln: vuln1,
			opt: remediation.Options{
				DevDeps:     true,
				MaxDepth:    -1,
				IgnoreVulns: []string{"OSV-2"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.opt.MatchVuln(tt.vuln); got != tt.want {
				t.Errorf("MatchVuln() = %v, want %v", got, tt.want)
			}
		})
	}
}
