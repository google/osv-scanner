package grouper_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scanner/v2/internal/grouper"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

func newEcosystemSpecific(t *testing.T, fields map[string]any) *structpb.Struct {
	t.Helper()

	es, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatal(err)
	}

	return es
}

func cvssV3(score string) []*osvschema.Severity {
	return []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: score}}
}

func uncalledInventory() *extractor.Package {
	return &extractor.Package{
		ExploitabilitySignals: []*vex.PackageExploitabilitySignal{{
			Justification:   vex.VulnerableCodeNotInExecutePath,
			MatchesAllVulns: true,
		}},
	}
}

func TestBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                          string
		pkg                           models.PackageVulns
		considerExploitabilitySignals bool
		want                          []models.GroupInfo
	}{
		{
			name: "no_vulnerabilities",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
			},
			want: []models.GroupInfo{},
		},
		{
			name: "one_vulnerability_with_a_severity",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
				Vulnerabilities: []*osvschema.Vulnerability{
					{Id: "OSV-1", Severity: cvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")},
				},
			},
			want: []models.GroupInfo{
				{IDs: []string{"OSV-1"}, Aliases: []string{"OSV-1"}, MaxSeverity: "8.8"},
			},
		},
		{
			name: "one_vulnerability_without_a_usable_severity",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
				Vulnerabilities: []*osvschema.Vulnerability{
					{Id: "OSV-1", Severity: []*osvschema.Severity{{Score: "1"}}},
				},
			},
			want: []models.GroupInfo{
				{IDs: []string{"OSV-1"}, Aliases: []string{"OSV-1"}},
			},
		},
		{
			name: "two_unrelated_vulnerabilities",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
				Vulnerabilities: []*osvschema.Vulnerability{
					{Id: "OSV-1"},
					{Id: "OSV-2"},
				},
			},
			want: []models.GroupInfo{
				{IDs: []string{"OSV-1"}, Aliases: []string{"OSV-1"}},
				{IDs: []string{"OSV-2"}, Aliases: []string{"OSV-2"}},
			},
		},
		{
			name: "two_aliases_of_a_single_vulnerability_with_a_max_severity",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
				Vulnerabilities: []*osvschema.Vulnerability{
					{Id: "OSV-1", Severity: cvssV3("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N")},
					{Id: "GHSA-123", Aliases: []string{"OSV-1"}, Severity: cvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L")},
				},
			},
			want: []models.GroupInfo{
				{IDs: []string{"OSV-1", "GHSA-123"}, Aliases: []string{"GHSA-123", "OSV-1"}, MaxSeverity: "8.3"},
			},
		},
		{
			name: "two_aliases_of_a_single_vulnerability_without_a_max_severity",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
				Vulnerabilities: []*osvschema.Vulnerability{
					{Id: "OSV-1", Severity: []*osvschema.Severity{{Type: osvschema.Severity_Ubuntu, Score: "negligible"}}},
					{Id: "GHSA-123", Aliases: []string{"OSV-1"}},
				},
			},
			want: []models.GroupInfo{
				{IDs: []string{"OSV-1", "GHSA-123"}, Aliases: []string{"GHSA-123", "OSV-1"}},
			},
		},
		{
			name: "debian_package_with_an_unimportant_vulnerability",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "libxml2", Version: "2.9.14+dfsg-1.3", Ecosystem: "Debian:12"},
				Vulnerabilities: []*osvschema.Vulnerability{
					{
						Id: "DEBIAN-CVE-2024-0001",
						Affected: []*osvschema.Affected{{
							EcosystemSpecific: newEcosystemSpecific(t, map[string]any{"urgency": "unimportant"}),
						}},
					},
					{
						Id: "DEBIAN-CVE-2024-0002",
						Affected: []*osvschema.Affected{{
							EcosystemSpecific: newEcosystemSpecific(t, map[string]any{"urgency": "low"}),
						}},
					},
				},
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{"DEBIAN-CVE-2024-0001"},
					Aliases: []string{"DEBIAN-CVE-2024-0001"},
					ExperimentalAnalysis: map[string]models.AnalysisInfo{
						"DEBIAN-CVE-2024-0001": {Called: true, Unimportant: true},
					},
				},
				{IDs: []string{"DEBIAN-CVE-2024-0002"}, Aliases: []string{"DEBIAN-CVE-2024-0002"}},
			},
		},
		{
			name: "ubuntu_package_with_unimportant_vulnerabilities",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "openssl", Version: "3.0.2-0ubuntu1.15", Ecosystem: "Ubuntu:22.04"},
				Vulnerabilities: []*osvschema.Vulnerability{
					{
						Id:       "UBUNTU-CVE-2024-0003",
						Severity: []*osvschema.Severity{{Type: osvschema.Severity_Ubuntu, Score: "negligible"}},
					},
					{
						Id: "UBUNTU-CVE-2024-0004",
						Severity: []*osvschema.Severity{
							{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"},
							{Type: osvschema.Severity_Ubuntu, Score: "medium"},
						},
					},
					{
						// older records have the priority as ecosystem specific data
						Id: "UBUNTU-CVE-2024-0005",
						Affected: []*osvschema.Affected{{
							EcosystemSpecific: newEcosystemSpecific(t, map[string]any{"ubuntu_priority": "negligible"}),
						}},
					},
				},
			},
			want: []models.GroupInfo{
				{
					IDs:     []string{"UBUNTU-CVE-2024-0003"},
					Aliases: []string{"UBUNTU-CVE-2024-0003"},
					ExperimentalAnalysis: map[string]models.AnalysisInfo{
						"UBUNTU-CVE-2024-0003": {Called: true, Unimportant: true},
					},
				},
				{
					IDs:         []string{"UBUNTU-CVE-2024-0004"},
					Aliases:     []string{"UBUNTU-CVE-2024-0004"},
					MaxSeverity: "8.1",
				},
				{
					IDs:     []string{"UBUNTU-CVE-2024-0005"},
					Aliases: []string{"UBUNTU-CVE-2024-0005"},
					ExperimentalAnalysis: map[string]models.AnalysisInfo{
						"UBUNTU-CVE-2024-0005": {Called: true, Unimportant: true},
					},
				},
			},
		},
		{
			// only vulnerabilities in debian-based ecosystems can be unimportant
			name: "vulnerability_tagged_as_unimportant_outside_of_a_debian_based_ecosystem",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
				Vulnerabilities: []*osvschema.Vulnerability{
					{
						Id: "OSV-1",
						Affected: []*osvschema.Affected{{
							EcosystemSpecific: newEcosystemSpecific(t, map[string]any{"urgency": "unimportant"}),
						}},
					},
				},
			},
			want: []models.GroupInfo{
				{IDs: []string{"OSV-1"}, Aliases: []string{"OSV-1"}},
			},
		},
		{
			name: "exploitability_signals_are_ignored_when_not_considered",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "mine1",
					Version:   "1.2.3",
					Ecosystem: "npm",
					Inventory: uncalledInventory(),
				},
				Vulnerabilities: []*osvschema.Vulnerability{{Id: "OSV-1"}},
			},
			considerExploitabilitySignals: false,
			want: []models.GroupInfo{
				{IDs: []string{"OSV-1"}, Aliases: []string{"OSV-1"}},
			},
		},
		{
			name: "one_called_vulnerability",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "mine1",
					Version:   "1.2.3",
					Ecosystem: "npm",
					Inventory: &extractor.Package{},
				},
				Vulnerabilities: []*osvschema.Vulnerability{{Id: "OSV-1"}},
			},
			considerExploitabilitySignals: true,
			want: []models.GroupInfo{
				{
					IDs:     []string{"OSV-1"},
					Aliases: []string{"OSV-1"},
					ExperimentalAnalysis: map[string]models.AnalysisInfo{
						"OSV-1": {Called: true},
					},
				},
			},
		},
		{
			name: "two_aliases_of_a_single_uncalled_vulnerability",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "mine1",
					Version:   "1.2.3",
					Ecosystem: "npm",
					Inventory: uncalledInventory(),
				},
				Vulnerabilities: []*osvschema.Vulnerability{
					{Id: "OSV-1"},
					{Id: "GHSA-123", Aliases: []string{"OSV-1"}},
				},
			},
			considerExploitabilitySignals: true,
			want: []models.GroupInfo{
				{
					IDs:     []string{"OSV-1", "GHSA-123"},
					Aliases: []string{"GHSA-123", "OSV-1"},
					ExperimentalAnalysis: map[string]models.AnalysisInfo{
						"OSV-1":    {Called: false},
						"GHSA-123": {Called: false},
					},
				},
			},
		},
		{
			name: "uncalled_unimportant_vulnerability",
			pkg: models.PackageVulns{
				Package: models.PackageInfo{
					Name:      "libxml2",
					Version:   "2.9.14+dfsg-1.3",
					Ecosystem: "Debian:12",
					Inventory: uncalledInventory(),
				},
				Vulnerabilities: []*osvschema.Vulnerability{
					{
						Id: "DEBIAN-CVE-2024-0001",
						Affected: []*osvschema.Affected{{
							EcosystemSpecific: newEcosystemSpecific(t, map[string]any{"urgency": "unimportant"}),
						}},
					},
				},
			},
			considerExploitabilitySignals: true,
			want: []models.GroupInfo{
				{
					IDs:     []string{"DEBIAN-CVE-2024-0001"},
					Aliases: []string{"DEBIAN-CVE-2024-0001"},
					ExperimentalAnalysis: map[string]models.AnalysisInfo{
						"DEBIAN-CVE-2024-0001": {Called: false, Unimportant: true},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := grouper.Build(tt.pkg, tt.considerExploitabilitySignals)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Build() returned an unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
