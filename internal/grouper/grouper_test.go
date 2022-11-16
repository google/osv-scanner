package grouper

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"
)

func TestGroup(t *testing.T) {
	// Should be grouped by IDs appearing in alias.
	v1 := osv.Vulnerability{
		ID: "CVE-1",
		Aliases: []string{
			"FOO-1",
		},
	}
	v2 := osv.Vulnerability{
		ID:      "FOO-1",
		Aliases: []string{},
	}
	v3 := osv.Vulnerability{
		ID: "FOO-2",
		Aliases: []string{
			"FOO-1",
		},
	}

	// Should be grouped by aliases intersecting.
	v4 := osv.Vulnerability{
		ID: "BAR-1",
		Aliases: []string{
			"CVE-2",
			"CVE-3",
		},
	}
	v5 := osv.Vulnerability{
		ID: "BAR-2",
		Aliases: []string{
			"CVE-3",
			"CVE-4",
		},
	}
	v6 := osv.Vulnerability{
		ID: "BAR-3",
		Aliases: []string{
			"CVE-4",
		},
	}

	// Unrelated.
	v7 := osv.Vulnerability{
		ID: "UNRELATED-1",
		Aliases: []string{
			"BAR-1337",
		},
	}
	v8 := osv.Vulnerability{
		ID: "UNRELATED-2",
		Aliases: []string{
			"BAR-1338",
		},
	}

	for _, tc := range []struct {
		vulns []osv.Vulnerability
		want  []GroupedVulnerabilities
	}{
		{
			vulns: []osv.Vulnerability{
				v1, v2, v3, v4, v5, v6, v7, v8,
			},
			want: []GroupedVulnerabilities{
				GroupedVulnerabilities{
					v1, v2, v3,
				},
				GroupedVulnerabilities{
					v4, v5, v6,
				},
				GroupedVulnerabilities{
					v7,
				},
				GroupedVulnerabilities{
					v8,
				},
			},
		},
		{
			vulns: []osv.Vulnerability{
				v8, v2, v1, v5, v7, v4, v6, v3,
			},
			want: []GroupedVulnerabilities{
				GroupedVulnerabilities{
					v8,
				},
				GroupedVulnerabilities{
					v2, v1, v3,
				},
				GroupedVulnerabilities{
					v5, v4, v6,
				},
				GroupedVulnerabilities{
					v7,
				},
			},
		},
	} {
		grouped := Group(tc.vulns)
		if diff := cmp.Diff(tc.want, grouped); diff != "" {
			t.Errorf("GroupedVulns() returned an unexpected result (-want, +got):\n%s", diff)
		}

	}
}
