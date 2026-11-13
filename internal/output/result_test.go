package output

import (
	"testing"

	"github.com/google/go-cmp/cmp"
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

func Test_groupSARIFFindings(t *testing.T) {
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

			got := groupSARIFFindings(&tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}

func Test_groupSARIFFindings_Merging(t *testing.T) {
	t.Parallel()

	source := models.SourceInfo{Path: "/path/to/lockfile", Type: models.SourceTypeProjectPackage}

	pkgVulns := func(name, version string, vulns ...*osvschema.Vulnerability) models.PackageVulns {
		group := models.GroupInfo{}
		for _, v := range vulns {
			group.IDs = append(group.IDs, v.GetId())
			group.Aliases = append(group.Aliases, v.GetId())
			group.Aliases = append(group.Aliases, v.GetAliases()...)
		}

		return models.PackageVulns{
			Package:         models.PackageInfo{Name: name, Version: version, Ecosystem: "npm"},
			Vulnerabilities: vulns,
			Groups:          []models.GroupInfo{group},
		}
	}

	type groupSummary struct {
		DisplayID     string
		AliasedIDList []string
		Packages      []string
	}

	tests := []struct {
		name     string
		packages []models.PackageVulns
		want     []groupSummary
	}{
		{
			name: "packages_sharing_only_an_alias_are_merged",
			packages: []models.PackageVulns{
				pkgVulns("pkg-a", "1.0.0", &osvschema.Vulnerability{Id: "GHSA-1", Aliases: []string{"CVE-1"}}),
				pkgVulns("pkg-b", "1.0.0", &osvschema.Vulnerability{Id: "GO-1", Aliases: []string{"CVE-1"}}),
			},
			want: []groupSummary{
				{DisplayID: "CVE-1", AliasedIDList: []string{"CVE-1", "GO-1", "GHSA-1"}, Packages: []string{"pkg-a@1.0.0", "pkg-b@1.0.0"}},
			},
		},
		{
			name: "package_bridging_two_groups_merges_them",
			packages: []models.PackageVulns{
				pkgVulns("pkg-a", "1.0.0", &osvschema.Vulnerability{Id: "GHSA-1"}),
				pkgVulns("pkg-b", "1.0.0", &osvschema.Vulnerability{Id: "GO-1"}),
				pkgVulns("pkg-c", "1.0.0", &osvschema.Vulnerability{Id: "GHSA-1"}, &osvschema.Vulnerability{Id: "GO-1"}),
			},
			want: []groupSummary{
				{DisplayID: "GO-1", AliasedIDList: []string{"GO-1", "GHSA-1"}, Packages: []string{"pkg-a@1.0.0", "pkg-b@1.0.0", "pkg-c@1.0.0"}},
			},
		},
		{
			name: "distinct_versions_and_unrelated_groups_are_kept",
			packages: []models.PackageVulns{
				pkgVulns("pkg-a", "1.2.3", &osvschema.Vulnerability{Id: "OSV-2"}),
				pkgVulns("pkg-a", "1.2.2", &osvschema.Vulnerability{Id: "OSV-2"}),
				pkgVulns("pkg-b", "1.0.0", &osvschema.Vulnerability{Id: "OSV-1"}),
			},
			want: []groupSummary{
				{DisplayID: "OSV-1", AliasedIDList: []string{"OSV-1"}, Packages: []string{"pkg-b@1.0.0"}},
				{DisplayID: "OSV-2", AliasedIDList: []string{"OSV-2"}, Packages: []string{"pkg-a@1.2.2", "pkg-a@1.2.3"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			groups := groupSARIFFindings(&models.VulnerabilityResults{
				Results: []models.PackageSource{{Source: source, Packages: tt.packages}},
			})

			got := make([]groupSummary, 0, len(groups))
			for _, g := range groups {
				summary := groupSummary{DisplayID: g.DisplayID, AliasedIDList: g.AliasedIDList}
				for _, pws := range g.PkgSource.StableKeys() {
					summary.Packages = append(summary.Packages, pws.Package.Name+"@"+pws.Package.Version)
				}
				got = append(got, summary)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("groupSARIFFindings() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
