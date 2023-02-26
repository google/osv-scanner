package sourceanalysis

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/vuln/exp/govulncheck"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadHelper[[]models.PackageVulns](t, "fixtures/input.json")
	gvcResByVulnID := testutility.LoadHelper[map[string]*govulncheck.Vuln](t, "fixtures/govulncheckinput.json")
	vulnsByID := testutility.LoadHelper[map[string]models.Vulnerability](t, "fixtures/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)
	testutility.AssertMatchFixtureJSON(t, "fixtures/output.json", pkgs)
}
