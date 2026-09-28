// Package grouper groups vulnerabilities by aliases, then sorts them.
package grouper

import (
	"maps"
	"slices"
	"sort"

	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// disjointSet is a disjoint-set forest over record indices, where each element
// is the index of its parent, and a leader is an element that is its own parent
type disjointSet []int

// find returns the leader of the set that n is in
func (d disjointSet) find(n int) int {
	if d[n] == n {
		return n
	}

	return d.find(d[n])
}

// union merges the sets that a and b are in, by making the larger leader follow
// the smaller one, so that the leader of each set is always its earliest record
func (d disjointSet) union(a, b int) {
	al := d.find(a)
	bl := d.find(b)

	if al == bl {
		return
	}

	d[max(al, bl)] = min(al, bl)
}

// newDisjointSet returns a disjoint-set forest of n elements, each in their own set
func newDisjointSet(n int) disjointSet {
	d := make(disjointSet, n)

	for i := range d {
		d[i] = i
	}

	return d
}

// Group groups vulnerabilities by aliases.
func Group(vulns []IDAliases) []models.GroupInfo {
	// tracks the first record to have each identifier, so we can tell which
	// earlier record (if any) a later record shares an identifier with
	refs := make(map[string]int)
	groups := newDisjointSet(len(vulns))

	for i, vuln := range vulns {
		for _, id := range slices.Concat([]string{vuln.ID}, vuln.Aliases) {
			// if an earlier record has already claimed this identifier, then we're for the
			// same vulnerability so should be in the same group; otherwise we claim it
			if l, ok := refs[id]; ok {
				groups.union(i, l)
			} else {
				refs[id] = i
			}
		}
	}

	// Extract groups into the final result structure, using each group's leader as its ID.
	extractedGroups := map[int][]string{}
	extractedAliases := map[int][]string{}
	for i := range vulns {
		gid := groups.find(i)
		extractedGroups[gid] = append(extractedGroups[gid], vulns[i].ID)
		extractedAliases[gid] = append(extractedAliases[gid], vulns[i].Aliases...)
	}

	// sort by group ID, which as the leader of each group is its earliest record,
	// so that groups are in the order their records first appear
	sortedKeys := slices.AppendSeq(make([]int, 0, len(extractedGroups)), maps.Keys(extractedGroups))
	sort.Ints(sortedKeys)

	result := make([]models.GroupInfo, 0, len(sortedKeys))
	for _, key := range sortedKeys {
		// Sort the strings so they are always in the same order
		slices.SortFunc(extractedGroups[key], identifiers.IDSortFunc)

		// Add IDs to aliases
		extractedAliases[key] = append(extractedAliases[key], extractedGroups[key]...)

		// Dedup entries
		sort.Strings(extractedAliases[key])
		extractedAliases[key] = slices.Compact(extractedAliases[key])

		result = append(result, models.GroupInfo{IDs: extractedGroups[key], Aliases: extractedAliases[key]})
	}

	return result
}
