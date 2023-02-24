package sourceanalysis

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/vuln/exp/govulncheck"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := loadHelper[[]models.PackageVulns](t, "fixtures/input.json")
	gvcResByVulnID := loadHelper[map[string]*govulncheck.Vuln](t, "fixtures/govulncheckinput.json")
	vulnsByID := loadHelper[map[string]models.Vulnerability](t, "fixtures/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)
	snaps.MatchJSON(t, pkgs)
}

func loadHelper[V any](t *testing.T, path string) V {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open fixture: %s", err)
	}
	var value V
	err = json.NewDecoder(file).Decode(&value)
	if err != nil {
		t.Fatalf("Failed to parse fixture: %s", err)
	}

	return value
}
