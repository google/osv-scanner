package sourceanalysis

import (
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/vuln/exp/govulncheck"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "fixtures/input.json")
	gvcResByVulnID := testutility.LoadJSONFixture[map[string]*govulncheck.Vuln](t, "fixtures/govulncheckinput.json")
	vulnsByID := testutility.LoadJSONFixture[map[string]models.Vulnerability](t, "fixtures/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)
	testutility.AssertMatchFixtureJSON(t, "fixtures/output.json", pkgs)
}
