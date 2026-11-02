package output

import (
	"slices"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func Test_groupFixedVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []models.VulnerabilityFlattened
		want testutility.Snapshot
	}{
		{
			name: "",
			args: testutility.LoadJSONFixture[[]models.VulnerabilityFlattened](t, "testdata/flattened_vulns.json"),
			want: testutility.NewSnapshot(),
		},
		{
			name: "",
			args: testutility.LoadJSONFixtureWithWindowsReplacements[[]models.VulnerabilityFlattened](t,
				"testdata/flattened_vulns.json",
				map[string]string{
					"/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock",
					"/path/to/scorecard-check-osv-e2e/go.mod":                      "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod",
				},
			),
			want: testutility.NewSnapshot().WithWindowsReplacements(
				map[string]string{
					"D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock": "/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock",
					"D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod":                         "/path/to/scorecard-check-osv-e2e/go.mod",
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := groupFixedVersions(tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}

func Test_mapIDsToGroupedSARIFFinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args models.VulnerabilityResults
		want testutility.Snapshot
	}{
		{
			args: testutility.LoadJSONFixtureWithWindowsReplacements[models.VulnerabilityResults](t,
				"testdata/test-vuln-results-a.json",
				map[string]string{
					"/path/to/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock",
					"/path/to/go.mod":                      "D:\\\\path\\\\to\\\\go.mod",
				},
			),
			want: testutility.NewSnapshot().WithWindowsReplacements(
				map[string]string{
					"D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock": "/path/to/sub-rust-project/Cargo.lock",
					"D:\\\\path\\\\to\\\\go.mod":                         "/path/to/go.mod",
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := mapIDsToGroupedSARIFFinding(&tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}

// A group known by several identifiers is one group, and must be reported once.
// Returning a map keyed by identifier made it one entry per identifier, and
// PrintSARIFReport turned each entry into a byte-identical SARIF result.
func Test_mapIDsToGroupedSARIFFinding_reportsEachAliasGroupOnce(t *testing.T) {
	t.Parallel()

	results := models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: "one/lockfile"},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
						Groups: []models.GroupInfo{{
							IDs:     []string{"OSV-1", "GHSA-1"},
							Aliases: []string{"OSV-1", "GHSA-1", "CVE-1"},
						}},
						Vulnerabilities: []*osvschema.Vulnerability{{
							Id:      "OSV-1",
							Aliases: []string{"GHSA-1", "CVE-1"},
						}},
					},
				},
			},
		},
	}

	groups := mapIDsToGroupedSARIFFinding(&results)

	if len(groups) != 1 {
		t.Fatalf("expected 1 group for one alias group, got %d", len(groups))
	}
	if len(groups[0].PkgSource) != 1 {
		t.Errorf("expected the group to hold one package, got %d", len(groups[0].PkgSource))
	}
	if got, want := groups[0].AliasedIDList, []string{"CVE-1", "OSV-1", "GHSA-1"}; !slices.Equal(got, want) {
		t.Errorf("expected identifiers %v, got %v", want, got)
	}
}

// A package can bridge two groups: matching on IDs alone would keep whichever
// group was seen first and silently drop the other. Two packages that share a
// CVE alias must end up in a single group, while an unrelated package stays on
// its own.
func Test_mapIDsToGroupedSARIFFinding_mergesGroupsSharingAnAlias(t *testing.T) {
	t.Parallel()

	vuln := func(id string, aliases []string) *osvschema.Vulnerability {
		return &osvschema.Vulnerability{Id: id, Aliases: aliases}
	}
	pkg := func(name, version, id string, aliases []string) models.PackageVulns {
		return models.PackageVulns{
			Package:         models.PackageInfo{Name: name, Version: version, Ecosystem: "npm"},
			Groups:          []models.GroupInfo{{IDs: []string{id}, Aliases: aliases}},
			Vulnerabilities: []*osvschema.Vulnerability{vuln(id, aliases)},
		}
	}

	results := models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source:   models.SourceInfo{Path: "first/lockfile"},
				Packages: []models.PackageVulns{pkg("mine1", "1.2.2", "OSV-A", []string{"OSV-A", "CVE-1"})},
			},
			{
				Source:   models.SourceInfo{Path: "second/lockfile"},
				Packages: []models.PackageVulns{pkg("mine2", "3.2.5", "OSV-B", []string{"OSV-B", "CVE-1"})},
			},
			{
				Source:   models.SourceInfo{Path: "third/lockfile"},
				Packages: []models.PackageVulns{pkg("mine3", "0.4.1", "OSV-C", nil)},
			},
		},
	}

	groups := mapIDsToGroupedSARIFFinding(&results)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	merged := groups[0]
	if merged.DisplayID != "CVE-1" {
		t.Errorf("expected the merged group to be displayed as CVE-1, got %q", merged.DisplayID)
	}
	if len(merged.PkgSource) != 2 {
		t.Errorf("expected the merged group to hold both packages, got %d", len(merged.PkgSource))
	}
	if len(merged.AliasedVulns) != 2 {
		t.Errorf("expected both vulnerabilities in the merged group, got %d", len(merged.AliasedVulns))
	}
	if !slices.Contains(merged.AliasedIDList, "CVE-1") {
		t.Errorf("expected the shared alias to be kept, got %v", merged.AliasedIDList)
	}

	standalone := groups[1]
	if standalone.DisplayID != "OSV-C" {
		t.Errorf("expected the standalone group to be OSV-C, got %q", standalone.DisplayID)
	}
	if len(standalone.PkgSource) != 1 {
		t.Errorf("expected the standalone group to hold one package, got %d", len(standalone.PkgSource))
	}
}
