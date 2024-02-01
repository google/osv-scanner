package sourceanalysis

import (
	"testing"

	"github.com/google/osv-scanner/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "fixtures-go/input.json")
	gvcResByVulnID := testutility.LoadJSONFixture[map[string][]*govulncheck.Finding](t, "fixtures-go/govulncheckinput.json")
	vulnsByID := testutility.LoadJSONFixture[map[string]models.Vulnerability](t, "fixtures-go/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
}

func Test_matchEmptyAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "fixtures-go/input-no-call-data.json")
	// When there is no ecosystem specific data, govulncheck will return no results
	gvcResByVulnID := map[string][]*govulncheck.Finding{}
	vulnsByID := testutility.LoadJSONFixture[map[string]models.Vulnerability](t, "fixtures-go/vulnbyid-no-call-data.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
}
