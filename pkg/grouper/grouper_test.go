package grouper

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/pkg/models"
)

func TestGroup(t *testing.T) {
	// Should be grouped by IDs appearing in alias.
	v1 := IDAliases{
		ID: "CVE-1",
		Aliases: []string{
			"FOO-1",
		},
	}
	v2 := IDAliases{
		ID:      "FOO-1",
		Aliases: []string{},
	}
	v3 := IDAliases{
		ID: "FOO-2",
		Aliases: []string{
			"FOO-1",
		},
	}

	// Should be grouped by aliases intersecting.
	v4 := IDAliases{
		ID: "BAR-1",
		Aliases: []string{
			"CVE-2",
			"CVE-3",
		},
	}
	v5 := IDAliases{
		ID: "BAR-2",
		Aliases: []string{
			"CVE-3",
			"CVE-4",
		},
	}
	v6 := IDAliases{
		ID: "BAR-3",
		Aliases: []string{
			"CVE-4",
		},
	}

	// Unrelated.
	v7 := IDAliases{
		ID: "UNRELATED-1",
		Aliases: []string{
			"BAR-1337",
		},
	}
	v8 := IDAliases{
		ID: "UNRELATED-2",
		Aliases: []string{
			"BAR-1338",
		},
	}

	// Unrelated, empty aliases
	v9 := IDAliases{
		ID: "UNRELATED-3",
	}
	v10 := IDAliases{
		ID: "UNRELATED-4",
	}

	for _, tc := range []struct {
		vulns []IDAliases
		want  []models.GroupInfo
	}{
		{
			vulns: []IDAliases{
				v1, v2, v3, v4, v5, v6, v7, v8,
			},
			want: []models.GroupInfo{
				{
					IDs: []string{v1.ID, v2.ID, v3.ID},
				},
				{
					IDs: []string{v4.ID, v5.ID, v6.ID},
				},
				{
					IDs: []string{v7.ID},
				},
				{
					IDs: []string{v8.ID},
				},
			},
		},
		{
			vulns: []IDAliases{
				v8, v2, v1, v5, v7, v4, v6, v3, v9, v10,
			},
			want: []models.GroupInfo{
				{
					IDs: []string{v8.ID},
				},
				{
					IDs: []string{v2.ID, v1.ID, v3.ID},
				},
				{
					IDs: []string{v5.ID, v4.ID, v6.ID},
				},
				{
					IDs: []string{v7.ID},
				},
				{
					IDs: []string{v9.ID},
				},
				{
					IDs: []string{v10.ID},
				},
			},
		},
		{
			vulns: []IDAliases{
				v9, v10,
			},
			want: []models.GroupInfo{
				{
					IDs: []string{v9.ID},
				},
				{
					IDs: []string{v10.ID},
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
