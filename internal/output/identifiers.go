package output

import "strings"

// idSortFunc sorts IDs ascending by CVE < [ECO-SPECIFIC] < GHSA
func idSortFunc(a, b string) int {
	aIsCVE := strings.HasPrefix(strings.ToUpper(a), "CVE")
	bIsCVE := strings.HasPrefix(strings.ToUpper(b), "CVE")
	if aIsCVE || bIsCVE {
		if aIsCVE == bIsCVE {
			// Both are CVEs, order by alphanumerically
			return strings.Compare(a, b)
		} else if aIsCVE {
			// Only aIsCVE
			return -1
		} else {
			// Only bIsCVE
			return 1
		}
	}

	// Neither is CVE
	aIsGHSA := strings.HasPrefix(strings.ToUpper(a), "GHSA")
	bIsGHSA := strings.HasPrefix(strings.ToUpper(b), "GHSA")
	if aIsGHSA || bIsGHSA {
		if aIsGHSA == bIsGHSA {
			// Both are CVEs, order by alphanumerically
			return strings.Compare(a, b)
		} else if aIsGHSA {
			// Only aIsGHSA // 1, and -1 are intentionally swapped from CVEs
			return 1
		} else {
			// Only bIsGHSA
			return -1
		}
	}

	// Neither is GHSA
	return strings.Compare(a, b)
}
