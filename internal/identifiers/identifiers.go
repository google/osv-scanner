// Package identifiers provides functions for sorting vulnerability identifiers.
package identifiers

import (
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// MostUpstreamsOrder orders by which vuln has the most upstreams,
// thereby finding the furthest downstream vuln identifier.
func MostUpstreamsOrder(a, b osvschema.Vulnerability) int {
	if len(a.Upstream) > len(b.Upstream) {
		return -1
	} else if len(a.Upstream) < len(b.Upstream) {
		return 1
	}

	return IDSortFunc(a.ID, b.ID)
}

func prefixOrder(prefix string) int {
	switch prefix {
	case "DSA", "USN":
		// Special case: For container scanning, DSA contains multiple CVEs and is more accurate.
		return 3
	case "CVE":
		// Highest precedence for normal cases
		return 2
	case "GHSA":
		// Lowest precedence
		return 0
	}

	return 1
}

func prefixOrderForDescription(prefix string) int {
	switch prefix {
	case "CVE":
		return 0
	case "GHSA":
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
