package identifiers

import (
	"strings"
)

func prefixOrder(prefix string) int {
	if prefix == "DSA" {
		// Special case: For container scanning, DSA contains multiple CVEs and is more accurate.
		return 3
	} else if prefix == "CVE" {
		// Highest precedence for normal cases
		return 2
	} else if prefix == "GHSA" {
		// Lowest precedence
		return 0
	}

	return 1
}

func prefixOrderForDescription(prefix string) int {
	if prefix == "CVE" {
		return 0
	} else if prefix == "GHSA" {
		return 1
	}

	return 2
}

func idSort(a, b string, prefixOrd func(string) int) int {
	prefixAOrd := prefixOrd(strings.Split(a, "-")[0])
	prefixBOrd := prefixOrd(strings.Split(b, "-")[0])

	if prefixAOrd > prefixBOrd {
		return -1
	} else if prefixAOrd < prefixBOrd {
		return 1
	}

	return strings.Compare(a, b)
}

// IDSortFunc sorts IDs ascending by CVE < [ECO-SPECIFIC] < GHSA
func IDSortFunc(a, b string) int {
	return idSort(a, b, prefixOrder)
}

// IDSortFuncForDescription sorts ID ascending by [ECO-SPECIFIC] < GHSA < CVE
func IDSortFuncForDescription(a, b string) int {
	return idSort(a, b, prefixOrderForDescription)
}
