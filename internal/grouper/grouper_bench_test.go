package grouper_test

import (
	"fmt"
	"testing"

	"github.com/google/osv-scanner/v2/internal/grouper"
)

// makeChainedVulns builds n vulnerabilities where every vulnerability shares one
// alias with its neighbour, so all of them end up in a single group through a
// chain of transitive alias relationships.
func makeChainedVulns(n int) []grouper.IDAliases {
	vulns := make([]grouper.IDAliases, 0, n)
	for i := range n {
		vulns = append(vulns, grouper.IDAliases{
			ID:      fmt.Sprintf("GHSA-%04d", i),
			Aliases: []string{fmt.Sprintf("CVE-%04d", i), fmt.Sprintf("CVE-%04d", i+1)},
		})
	}

	return vulns
}

// makeIsolatedVulns builds n vulnerabilities that share no identifiers.
func makeIsolatedVulns(n int) []grouper.IDAliases {
	vulns := make([]grouper.IDAliases, 0, n)
	for i := range n {
		vulns = append(vulns, grouper.IDAliases{
			ID:      fmt.Sprintf("GHSA-%04d", i),
			Aliases: []string{fmt.Sprintf("CVE-%04d", i)},
		})
	}

	return vulns
}

func BenchmarkGroup(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("chained/%d", n), func(b *testing.B) {
			vulns := makeChainedVulns(n)
			b.ReportAllocs()
			for b.Loop() {
				grouper.Group(vulns)
			}
		})
		b.Run(fmt.Sprintf("isolated/%d", n), func(b *testing.B) {
			vulns := makeIsolatedVulns(n)
			b.ReportAllocs()
			for b.Loop() {
				grouper.Group(vulns)
			}
		})
	}
}
