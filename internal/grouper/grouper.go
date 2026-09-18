// Package grouper groups vulnerabilities by aliases, then sorts them.
package grouper

import (
	"maps"
	"slices"
	"sort"

	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// Group groups vulnerabilities by aliases.
func Group(vulns []IDAliases) []models.GroupInfo {
	// Mapping of `vulns` index to a group ID. A group ID is just another index in the `vulns` slice.
	groups := make([]int, len(vulns))

	// Union-find over vulnerability indexes: two vulnerabilities belong to the
	// same group when they share an identifier (either ID or alias). Each
	// identifier is mapped to the first vulnerability it was seen on and any
	// later vulnerability carrying the same identifier is merged into it. This
	// is linear in the total number of identifiers rather than quadratic in the
	// number of vulnerabilities, and merges transitive chains correctly.
	parent := make([]int, len(vulns))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}

		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		// Keep the smaller index as the root so the root is also the group ID.
		if rb < ra {
			ra, rb = rb, ra
		}
		parent[rb] = ra
	}

	seen := make(map[string]int)
	link := func(identifier string, i int) {
		if j, ok := seen[identifier]; ok {
			union(i, j)
		} else {
			seen[identifier] = i
		}
	}
	for i, vuln := range vulns {
		link(vuln.ID, i)
		for _, alias := range vuln.Aliases {
			link(alias, i)
		}
	}

	// Resolve every vulnerability to its group's smallest index.
	for i := range vulns {
		groups[i] = find(i)
	}

	// Extract groups into the final result structure.
	extractedGroups := map[int][]string{}
	extractedAliases := map[int][]string{}
	for i, gid := range groups {
		extractedGroups[gid] = append(extractedGroups[gid], vulns[i].ID)
		extractedAliases[gid] = append(extractedAliases[gid], vulns[i].Aliases...)
	}

	// Sort by group ID to maintain stable order for tests.
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
