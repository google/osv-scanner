package grouper_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/v2/internal/grouper"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// permutations returns every ordering of the given items
func permutations[T any](items []T) [][]T {
	if len(items) <= 1 {
		return [][]T{slices.Clone(items)}
	}

	var result [][]T
	for i := range items {
		rest := slices.Concat(items[:i], items[i+1:])
		for _, perm := range permutations[T](rest) {
			result = append(result, append([]T{items[i]}, perm...))
		}
	}

	return result
}

func idsOf(vulns []grouper.IDAliases) string {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}

	return strings.Join(ids, ", ")
}

func TestGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		vulns []grouper.IDAliases
		want  []models.GroupInfo
	}{
		{
			name:  "no records",
			vulns: []grouper.IDAliases{},
			want:  []models.GroupInfo{},
		},
		{
			name: "record without aliases",
			vulns: []grouper.IDAliases{
				{ID: "GO-1"},
			},
			want: []models.GroupInfo{
				{IDs: []string{"GO-1"}, Aliases: []string{"GO-1"}},
			},
		},
		{
			name: "aliases include the id of the record",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"PYSEC-1", "CVE-1"}},
			},
			want: []models.GroupInfo{
				{IDs: []string{"GHSA-aaaa"}, Aliases: []string{"CVE-1", "GHSA-aaaa", "PYSEC-1"}},
			},
		},
		{
			name: "records with no identifiers in common",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1"}},
				{ID: "GHSA-bbbb", Aliases: []string{"CVE-2"}},
			},
			want: []models.GroupInfo{
				{IDs: []string{"GHSA-aaaa"}, Aliases: []string{"CVE-1", "GHSA-aaaa"}},
				{IDs: []string{"GHSA-bbbb"}, Aliases: []string{"CVE-2", "GHSA-bbbb"}},
			},
		},
		{
			name: "records sharing an alias",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1"}},
				{ID: "PYSEC-1", Aliases: []string{"CVE-1"}},
			},
			want: []models.GroupInfo{
				{IDs: []string{"PYSEC-1", "GHSA-aaaa"}, Aliases: []string{"CVE-1", "GHSA-aaaa", "PYSEC-1"}},
			},
		},
		{
			name: "record whose id is an alias of an earlier record",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"PYSEC-1"}},
				{ID: "PYSEC-1"},
			},
			want: []models.GroupInfo{
				{IDs: []string{"PYSEC-1", "GHSA-aaaa"}, Aliases: []string{"GHSA-aaaa", "PYSEC-1"}},
			},
		},
		{
			name: "record with an alias that is the id of an earlier record",
			vulns: []grouper.IDAliases{
				{ID: "PYSEC-1"},
				{ID: "GHSA-aaaa", Aliases: []string{"PYSEC-1"}},
			},
			want: []models.GroupInfo{
				{IDs: []string{"PYSEC-1", "GHSA-aaaa"}, Aliases: []string{"GHSA-aaaa", "PYSEC-1"}},
			},
		},
		{
			name: "record linking two existing groups merges them",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1"}},
				{ID: "GHSA-bbbb", Aliases: []string{"CVE-2"}},
				{ID: "GHSA-cccc", Aliases: []string{"CVE-1", "CVE-2"}},
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{"GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"},
					Aliases: []string{"CVE-1", "CVE-2", "GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"},
				},
			},
		},
		{
			// each record only shares an alias with its neighbours in the chain, and the
			// record linking the two halves together comes last
			name: "chain of records sharing aliases",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1"}},
				{ID: "GHSA-bbbb", Aliases: []string{"CVE-3"}},
				{ID: "GHSA-cccc", Aliases: []string{"CVE-2", "CVE-3"}},
				{ID: "GHSA-dddd", Aliases: []string{"CVE-1", "CVE-2"}},
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{"GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc", "GHSA-dddd"},
					Aliases: []string{"CVE-1", "CVE-2", "CVE-3", "GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc", "GHSA-dddd"},
				},
			},
		},
		{
			name: "chain of records linked only by the ids of other records",
			vulns: []grouper.IDAliases{
				{ID: "PYSEC-1"},
				{ID: "RUSTSEC-1"},
				{ID: "OSV-1", Aliases: []string{"RUSTSEC-1"}},
				{ID: "GHSA-aaaa", Aliases: []string{"PYSEC-1", "OSV-1"}},
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{"OSV-1", "PYSEC-1", "RUSTSEC-1", "GHSA-aaaa"},
					Aliases: []string{"GHSA-aaaa", "OSV-1", "PYSEC-1", "RUSTSEC-1"},
				},
			},
		},
		{
			// 0097/0096 share CVE-2023-31248, 0096/0095 share CVE-2023-1380, and
			// 0095/0102 share CVE-2023-1872
			name: "chain of livepatch notices",
			vulns: []grouper.IDAliases{
				{ID: "LSN-0097-1", Aliases: []string{"CVE-2023-31248"}},
				{ID: "LSN-0102-1", Aliases: []string{"CVE-2023-1872"}},
				{ID: "LSN-0095-1", Aliases: []string{"CVE-2023-1380", "CVE-2023-1872"}},
				{ID: "LSN-0096-1", Aliases: []string{"CVE-2023-1380", "CVE-2023-31248"}},
			},
			want: []models.GroupInfo{
				{
					IDs: []string{"LSN-0095-1", "LSN-0096-1", "LSN-0097-1", "LSN-0102-1"},
					Aliases: []string{
						"CVE-2023-1380", "CVE-2023-1872", "CVE-2023-31248",
						"LSN-0095-1", "LSN-0096-1", "LSN-0097-1", "LSN-0102-1",
					},
				},
			},
		},
		{
			name: "identifiers shared by multiple records are only included once",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1", "CVE-2"}},
				{ID: "PYSEC-1", Aliases: []string{"CVE-1", "CVE-2", "GHSA-aaaa"}},
			},
			want: []models.GroupInfo{
				{IDs: []string{"PYSEC-1", "GHSA-aaaa"}, Aliases: []string{"CVE-1", "CVE-2", "GHSA-aaaa", "PYSEC-1"}},
			},
		},
		{
			name: "ids are sorted by preference",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1"}},
				{ID: "PYSEC-1", Aliases: []string{"CVE-1"}},
				{ID: "CVE-1"},
				{ID: "USN-1", Aliases: []string{"CVE-1"}},
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{"USN-1", "CVE-1", "PYSEC-1", "GHSA-aaaa"},
					Aliases: []string{"CVE-1", "GHSA-aaaa", "PYSEC-1", "USN-1"},
				},
			},
		},
		{
			name: "groups are ordered by their earliest record",
			vulns: []grouper.IDAliases{
				{ID: "GO-2"},
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1"}},
				{ID: "GO-1"},
				{ID: "PYSEC-1", Aliases: []string{"CVE-1"}},
			},
			want: []models.GroupInfo{
				{IDs: []string{"GO-2"}, Aliases: []string{"GO-2"}},
				{IDs: []string{"PYSEC-1", "GHSA-aaaa"}, Aliases: []string{"CVE-1", "GHSA-aaaa", "PYSEC-1"}},
				{IDs: []string{"GO-1"}, Aliases: []string{"GO-1"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := grouper.Group(tt.vulns)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Group() returned an unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGroup_OrderIndependent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		vulns []grouper.IDAliases
	}{
		{
			name: "chain of records sharing aliases",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1"}},
				{ID: "GHSA-bbbb", Aliases: []string{"CVE-3"}},
				{ID: "GHSA-cccc", Aliases: []string{"CVE-2", "CVE-3"}},
				{ID: "GHSA-dddd", Aliases: []string{"CVE-1", "CVE-2"}},
			},
		},
		{
			name: "multiple groups, including a chain and unrelated records",
			vulns: []grouper.IDAliases{
				{ID: "GHSA-aaaa", Aliases: []string{"CVE-1"}},
				{ID: "GHSA-bbbb", Aliases: []string{"CVE-3"}},
				{ID: "GHSA-cccc", Aliases: []string{"CVE-2", "CVE-3"}},
				{ID: "GHSA-dddd", Aliases: []string{"CVE-1", "CVE-2"}},
				{ID: "PYSEC-1", Aliases: []string{"GHSA-eeee"}},
				{ID: "GHSA-eeee"},
				{ID: "GO-1"},
			},
		},
	}

	// the order of the groups follows the order of the records, so only what
	// is in each group should be the same regardless of the order
	ignoreGroupOrder := cmpopts.SortSlices(func(a, b models.GroupInfo) bool {
		return a.IDs[0] < b.IDs[0]
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want := grouper.Group(tt.vulns)

			for _, perm := range permutations(tt.vulns) {
				if diff := cmp.Diff(want, grouper.Group(perm), ignoreGroupOrder); diff != "" {
					// only report the first order that differs, as there can be thousands
					t.Fatalf("Group() returned a different result for the order [%s] (-want +got):\n%s", idsOf(perm), diff)
				}
			}
		})
	}
}
