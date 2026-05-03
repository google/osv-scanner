package osvscanner

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func Test_filterPackageVulns_orphanVulnKeptWhenAllGroupsIgnored(t *testing.T) {
	t.Parallel()

	// CVE-2023-1234 belongs to a group that is ignored by config.
	// CVE-2024-5678 is an orphan: it exists in Vulnerabilities but has no
	// corresponding group entry. Before the fix, the guard
	// `if len(newGroups) > 0` prevented the vuln loop from running when all
	// groups were filtered, so CVE-2024-5678 was silently dropped.
	pkgVulns := models.PackageVulns{
		Groups: []models.GroupInfo{
			{
				IDs:     []string{"CVE-2023-1234"},
				Aliases: []string{"CVE-2023-1234", "GHSA-abcd-1234-efgh"},
			},
		},
		Vulnerabilities: []*osvschema.Vulnerability{
			{Id: "CVE-2023-1234"},
			{Id: "CVE-2024-5678"},
		},
	}

	cfg := config.Config{
		IgnoredVulns: []*config.IgnoreEntry{
			{ID: "CVE-2023-1234", Reason: "test ignore"},
		},
	}

	got := filterPackageVulns(pkgVulns, cfg)

	if len(got.Groups) != 0 {
		t.Errorf("Groups after filter = %d, want 0", len(got.Groups))
	}

	if len(got.Vulnerabilities) != 1 {
		t.Errorf("Vulnerabilities after filter = %d, want 1", len(got.Vulnerabilities))
	}

	if len(got.Vulnerabilities) == 1 && got.Vulnerabilities[0].GetId() != "CVE-2024-5678" {
		t.Errorf("kept vuln = %q, want %q", got.Vulnerabilities[0].GetId(), "CVE-2024-5678")
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
