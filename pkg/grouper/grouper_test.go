package grouper_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/pkg/grouper"
	"github.com/google/osv-scanner/pkg/models"
)

func TestGroup(t *testing.T) {
	t.Parallel()

	// Should be grouped by IDs appearing in alias.
	v1 := grouper.IDAliases{
		ID: "CVE-1",
		Aliases: []string{
			"FOO-1",
		},
	}
	v2 := grouper.IDAliases{
		ID:      "FOO-1",
		Aliases: []string{},
	}
	v3 := grouper.IDAliases{
		ID: "FOO-2",
		Aliases: []string{
			"FOO-1",
		},
	}

	// Should be grouped by aliases intersecting.
	v4 := grouper.IDAliases{
		ID: "BAR-1",
		Aliases: []string{
			"CVE-2",
			"CVE-3",
		},
	}
	v5 := grouper.IDAliases{
		ID: "BAR-2",
		Aliases: []string{
			"CVE-3",
			"CVE-4",
		},
	}
	v6 := grouper.IDAliases{
		ID: "BAR-3",
		Aliases: []string{
			"CVE-4",
		},
	}

	// Unrelated.
	v7 := grouper.IDAliases{
		ID: "UNRELATED-1",
		Aliases: []string{
			"BAR-1337",
		},
	}
	v8 := grouper.IDAliases{
		ID: "UNRELATED-2",
		Aliases: []string{
			"BAR-1338",
		},
	}

	// Unrelated, empty aliases
	v9 := grouper.IDAliases{
		ID: "UNRELATED-3",
	}
	v10 := grouper.IDAliases{
		ID: "UNRELATED-4",
	}
	for _, tc := range []struct {
		vulns []grouper.IDAliases
		want  []models.GroupInfo
	}{
		{
			vulns: []grouper.IDAliases{
				v1, v2, v3, v4, v5, v6, v7, v8,
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{v1.ID, v2.ID, v3.ID},
					Aliases: []string{v1.ID, v2.ID, v3.ID},
				},
				{
					IDs:     []string{v4.ID, v5.ID, v6.ID},
					Aliases: []string{v4.ID, v5.ID, v6.ID, v4.Aliases[0], v4.Aliases[1], v5.Aliases[1]},
				},
				{
					IDs:     []string{v7.ID},
					Aliases: []string{v7.Aliases[0], v7.ID},
				},
				{
					IDs:     []string{v8.ID},
					Aliases: []string{v8.Aliases[0], v8.ID},
				},
			},
		},
		{
			vulns: []grouper.IDAliases{
				v8, v2, v1, v5, v7, v4, v6, v3, v9, v10,
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{v8.ID},
					Aliases: []string{v8.Aliases[0], v8.ID},
				},
				{
					IDs:     []string{v1.ID, v2.ID, v3.ID}, // Deterministic order
					Aliases: []string{v1.ID, v2.ID, v3.ID}, // Deterministic order
				},
				{
					IDs:     []string{v4.ID, v5.ID, v6.ID},
					Aliases: []string{v4.ID, v5.ID, v6.ID, v4.Aliases[0], v4.Aliases[1], v5.Aliases[1]},
				},
				{
					IDs:     []string{v7.ID},
					Aliases: []string{v7.Aliases[0], v7.ID},
				},
				{
					IDs:     []string{v9.ID},
					Aliases: []string{v9.ID},
				},
				{
					IDs:     []string{v10.ID},
					Aliases: []string{v10.ID},
				},
			},
		},
		{
			vulns: []grouper.IDAliases{
				v9, v10,
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{v9.ID},
					Aliases: []string{v9.ID},
				},
				{
					IDs:     []string{v10.ID},
					Aliases: []string{v10.ID},
				},
			},
		},
	} {
		grouped := grouper.Group(tc.vulns)
		if diff := cmp.Diff(tc.want, grouped); diff != "" {
			t.Errorf("GroupedVulns() returned an unexpected result (-want, +got):\n%s", diff)
		}
	}
}
