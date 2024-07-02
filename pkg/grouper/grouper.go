package grouper

import (
	"slices"
	"sort"

	"golang.org/x/exp/maps"

	"github.com/google/osv-scanner/pkg/models"
)

func hasAliasIntersection(v1, v2 IDAliases) bool {
	// Check if any aliases intersect.
	for _, alias := range v1.Aliases {
		if slices.Contains(v2.Aliases, alias) {
			return true
		}
	}
	// Check if either IDs are in the others' aliases.
	return slices.Contains(v1.Aliases, v2.ID) || slices.Contains(v2.Aliases, v1.ID)
}

// Group groups vulnerabilities by aliases.
func Group(vulns []IDAliases) []models.GroupInfo {
	// Mapping of `vulns` index to a group ID. A group ID is just another index in the `vulns` slice.
	groups := make([]int, len(vulns))

	// Initially make every vulnerability its own group.
	for i := 0; i < len(vulns); i++ {
		groups[i] = i
	}

	// Do a pair-wise (n^2) comparison and merge all intersecting vulns.
	for i := 0; i < len(vulns); i++ {
		for j := i + 1; j < len(vulns); j++ {
			if hasAliasIntersection(vulns[i], vulns[j]) {
				// Merge the two groups. Use the smaller index as the representative ID.
				groups[i] = min(groups[i], groups[j])
				groups[j] = groups[i]
			}
		}
	}

	// Extract groups into the final result structure.
	extractedGroups := map[int][]string{}
	extractedAliases := map[int][]string{}
	for i, gid := range groups {
		extractedGroups[gid] = append(extractedGroups[gid], vulns[i].ID)
		extractedAliases[gid] = append(extractedAliases[gid], vulns[i].Aliases...)
	}

	// Sort by group ID to maintain stable order for tests.
	sortedKeys := maps.Keys(extractedGroups)
	sort.Ints(sortedKeys)

	result := make([]models.GroupInfo, 0, len(sortedKeys))
	for _, key := range sortedKeys {
		// Sort the strings so they are always in the same order
		sort.Strings(extractedGroups[key])

		// Add IDs to aliases
		extractedAliases[key] = append(extractedAliases[key], extractedGroups[key]...)

		// Dedup entries
		sort.Strings(extractedAliases[key])
		extractedAliases[key] = slices.Compact(extractedAliases[key])

		result = append(result, models.GroupInfo{IDs: extractedGroups[key], Aliases: extractedAliases[key]})
	}

	return result
}
