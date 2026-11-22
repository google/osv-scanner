package sourceanalysis

import (
	"context"
	"slices"
	"testing"

	"github.com/google/osv-scanner/v2/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "testdata/json/input.json")
	gvcResByVulnID := testutility.LoadJSONFixture[map[string][]*govulncheck.Finding](t, "testdata/json/govulncheckinput.json")
	vulnsByID := testutility.LoadVulnMapFixture(t, "testdata/json/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
}

func Test_govulncheckCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		offline     bool
		wantOffline bool
	}{
		{
			name:        "online mode does not add offline env vars",
			offline:     false,
			wantOffline: false,
		},
		{
			name:        "offline mode adds GOPROXY=off and GOTOOLCHAIN=local env vars",
			offline:     true,
			wantOffline: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd := govulncheckCmd(context.Background(), "file:///test/db", "/test/mod", "1.21", tt.offline)
			hasGoproxyOff := slices.Contains(cmd.Env, "GOPROXY=off")
			hasToolchainLocal := slices.Contains(cmd.Env, "GOTOOLCHAIN=local")

			if hasGoproxyOff != tt.wantOffline {
				t.Errorf("govulncheckCmd() Env has GOPROXY=off = %v, want %v", hasGoproxyOff, tt.wantOffline)
			}
			if hasToolchainLocal != tt.wantOffline {
				t.Errorf("govulncheckCmd() Env has GOTOOLCHAIN=local = %v, want %v", hasToolchainLocal, tt.wantOffline)
			}
		})
	}
}

func Test_matchEmptyAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "testdata/json/input-no-call-data.json")
	// When there is no ecosystem specific data, govulncheck will return no results
	gvcResByVulnID := map[string][]*govulncheck.Finding{}
	vulnsByID := testutility.LoadVulnMapFixture(t, "testdata/json/vulnbyid-no-call-data.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
}
