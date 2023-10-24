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

func prefixOrderForDescription(prefix string) int {
	if prefix == "CVE" {
		return 0
	} else if prefix == "GHSA" {
		return 1
	}

	return 2
}

// idSortFunc sorts IDs ascending by CVE < [ECO-SPECIFIC] < GHSA
func idSortFunc(a, b string) int {
	return idSort(a, b, prefixOrder)
}

// idSortFuncForDescription sorts ID ascending by [ECO-SPECIFIC] < GHSA < CVE
func idSortFuncForDescription(a, b string) int {
	return idSort(a, b, prefixOrderForDescription)
}

func idSort(a, b string, prefixOrd func(string) int) int {
	prefixAOrd := prefixOrd(strings.Split(a, "-")[0])
	prefixBOrd := prefixOrd(strings.Split(b, "-")[0])

	if prefixAOrd > prefixBOrd {
		return -1
	} else if prefixAOrd < prefixBOrd {
		return 1
	} else {
		return strings.Compare(a, b)
	}
}
