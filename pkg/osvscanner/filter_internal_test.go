package osvscanner

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/imodels/results"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func Test_filterUnscannablePackages_shortCommitHash(t *testing.T) {
	t.Parallel()

	shortHash := "bca26e4"                                 // 7 chars -- what bun.lock stores
	fullHash := "bca26e4c1e3c1e3c1e3c1e3c1e3c1e3c1e3c1e3f" // 40 chars -- valid SHA1

	tests := []struct {
		name         string
		commit       string
		wantKept     int
		wantFiltered int
	}{
		{
			name:         "short hash is skipped",
			commit:       shortHash,
			wantKept:     0,
			wantFiltered: 0, // ShowAllPackages=false, so filtered slice is empty
		},
		{
			name:         "full hash is kept",
			commit:       fullHash,
			wantKept:     1,
			wantFiltered: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanResults := &results.ScanResults{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						{
							Name: "some-git-dep",
							SourceCode: &extractor.SourceCodeIdentifier{
								Commit: tt.commit,
							},
						},
					},
				},
				ConfigManager: config.Manager{
					DefaultConfig: config.Config{},
					ConfigMap:     make(map[string]config.Config),
				},
			}

			filtered := filterUnscannablePackages(scanResults, ScannerActions{})

			if len(scanResults.Inventory.Packages) != tt.wantKept {
				t.Errorf("packages kept = %d, want %d", len(scanResults.Inventory.Packages), tt.wantKept)
			}

			if len(filtered) != tt.wantFiltered {
				t.Errorf("packages in filtered slice = %d, want %d", len(filtered), tt.wantFiltered)
			}
		})
	}
}

func Test_filterPackageVulns_orphanVulnsPreserved(t *testing.T) {
	t.Parallel()

	// CVE-2024-001 is in both the group aliases and the vuln list.
	// CVE-2024-999 is in the vuln list but NOT referenced by any group alias.
	// When all groups are ignored (because CVE-2024-001 is ignored), the old guard
	// `if len(newGroups) > 0` would skip the vuln loop entirely, silently dropping
	// CVE-2024-999 even though it was never ignored.
	pkgVulns := models.PackageVulns{
		Groups: []models.GroupInfo{
			{
				IDs:     []string{"CVE-2024-001"},
				Aliases: []string{"CVE-2024-001"},
			},
		},
		Vulnerabilities: []*osvschema.Vulnerability{
			{Id: "CVE-2024-001"},
			{Id: "CVE-2024-999"},
		},
	}

	cfg := config.Config{
		IgnoredVulns: []*config.IgnoreEntry{
			{ID: "CVE-2024-001"},
		},
	}

	got := filterPackageVulns(pkgVulns, cfg)

	if len(got.Groups) != 0 {
		t.Errorf("groups after filter = %d, want 0", len(got.Groups))
	}

	if len(got.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities after filter = %d, want 1", len(got.Vulnerabilities))
	}

	if got.Vulnerabilities[0].GetId() != "CVE-2024-999" {
		t.Errorf("remaining vuln id = %q, want %q", got.Vulnerabilities[0].GetId(), "CVE-2024-999")
	}
}

func Test_filterResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want int
	}{
		{
			name: "filter_everything",
			path: "testdata/filter/all",
			want: 15,
		},
		{
			name: "filter_nothing",
			path: "testdata/filter/none",
			want: 0,
		},
		{
			name: "filter_partially",
			path: "testdata/filter/some",
			want: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// configManager looks for osv-scanner.toml in the source path.
			// Sources in the test input should point to files/folders in the testdata folder for this to work correctly.
			configManager := config.Manager{
				DefaultConfig: config.Config{},
				ConfigMap:     make(map[string]config.Config),
			}

			got := testutility.LoadJSONFixture[models.VulnerabilityResults](t, filepath.Join(tt.path, "input.json"))
			filtered := filterResults(&got, &configManager, false)

			testutility.NewSnapshot().MatchJSON(t, got)

			if filtered != tt.want {
				t.Errorf("filterResults() = %v, want %v", filtered, tt.want)
			}
		})
	}
}
