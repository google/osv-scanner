package output_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// aliasedGroupResults builds a VulnerabilityResults where a single package is
// matched by two advisories that alias each other into one group.
//
// This is the shape described in #3093: the group holds two IDs, so
// mapIDsToGroupedSARIFFinding registers two map keys pointing at the same
// *groupedSARIFFinding, and PrintSARIFReport used to emit one result per key.
func aliasedGroupResults() models.VulnerabilityResults {
	ghsa := &osvschema.Vulnerability{
		Id:      "GHSA-m5pq-gvj9-9vr8",
		Summary: "Regular expression denial of service",
		Details: "A denial of service vulnerability.",
		Aliases: []string{"RUSTSEC-2022-0013", "CVE-2022-24713"},
	}
	rustsec := &osvschema.Vulnerability{
		Id:      "RUSTSEC-2022-0013",
		Summary: "Regular expression denial of service",
		Details: "A denial of service vulnerability.",
		Aliases: []string{"GHSA-m5pq-gvj9-9vr8", "CVE-2022-24713"},
	}

	return models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: "/path/to/go.mod", Type: "lockfile"},
				Packages: []models.PackageVulns{
					{
						Package:         models.PackageInfo{Name: "regex", Version: "1.5.1", Ecosystem: "Go"},
						Vulnerabilities: []*osvschema.Vulnerability{ghsa, rustsec},
						Groups: []models.GroupInfo{
							{
								IDs:     []string{"GHSA-m5pq-gvj9-9vr8", "RUSTSEC-2022-0013"},
								Aliases: []string{"CVE-2022-24713", "GHSA-m5pq-gvj9-9vr8", "RUSTSEC-2022-0013"},
							},
						},
					},
				},
			},
		},
	}
}

func sarifResultCount(t *testing.T, res *models.VulnerabilityResults) int {
	t.Helper()

	var buf strings.Builder
	if err := output.PrintSARIFReport(res, &buf); err != nil {
		t.Fatalf("PrintSARIFReport() error: %v", err)
	}

	var report struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &report); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}

	return len(report.Runs[0].Results)
}

// TestPrintSARIFReport_NoDuplicateResultsPerAliasGroup ensures that a package
// matched by several advisories in the same alias group produces exactly one
// SARIF result, matching the one-row-per-alias-group behaviour of the table
// formatter. See #3093.
func TestPrintSARIFReport_NoDuplicateResultsPerAliasGroup(t *testing.T) {
	t.Parallel()

	res := aliasedGroupResults()

	if got := sarifResultCount(t, &res); got != 1 {
		t.Errorf("PrintSARIFReport() emitted %d results for a single alias group, want 1", got)
	}
}

// TestPrintSARIFReport_KeepsDistinctResults guards the fix: deduplication must
// only collapse repeats of the same group, so two different packages affected
// by the same alias group must still produce one result each.
func TestPrintSARIFReport_KeepsDistinctResults(t *testing.T) {
	t.Parallel()

	res := aliasedGroupResults()
	second := res.Results[0].Packages[0]
	second.Package = models.PackageInfo{Name: "regex", Version: "1.6.0", Ecosystem: "Go"}
	res.Results[0].Packages = append(res.Results[0].Packages, second)

	if got := sarifResultCount(t, &res); got != 2 {
		t.Errorf("PrintSARIFReport() emitted %d results for 2 distinct packages, want 2", got)
	}
}
