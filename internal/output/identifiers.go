package output

import (
	"strings"
)

func prefixOrder(prefix string) int {
	if prefix == "CVE" {
		// Highest precedence
		return 2
	} else if prefix == "GHSA" {
		// Lowest precedence
		return 0
	}

	return 1
}

// idSortFunc sorts IDs ascending by CVE < [ECO-SPECIFIC] < GHSA
func idSortFunc(a, b string) int {
	prefixAOrd := prefixOrder(strings.Split(a, "-")[0])
	prefixBOrd := prefixOrder(strings.Split(b, "-")[0])

	if prefixAOrd > prefixBOrd {
		return -1
	} else if prefixAOrd < prefixBOrd {
		return 1
	} else {
		return strings.Compare(a, b)
	}
}
