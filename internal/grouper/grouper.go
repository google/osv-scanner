package grouper

import (
	"sort"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type GroupedVulnerabilities []osv.Vulnerability

func hasAliasIntersection(v1, v2 osv.Vulnerability) bool {
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
func Group(vulns []osv.Vulnerability) []GroupedVulnerabilities {
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
	extractedGroups := map[int]GroupedVulnerabilities{}
	for i, gid := range groups {
		extractedGroups[gid] = append(extractedGroups[gid], vulns[i])
	}

	// Sort by group ID to maintain stable order for tests.
	sortedKeys := maps.Keys(extractedGroups)
	sort.Ints(sortedKeys)

	var result []GroupedVulnerabilities
	for _, key := range sortedKeys {
		result = append(result, extractedGroups[key])
	}
	return result
}
