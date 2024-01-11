package sourceanalysis

import (
	"testing"

	"github.com/google/osv-scanner/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/internal/testfixture"
	"github.com/google/osv-scanner/internal/testsnapshot"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testfixture.LoadJSON[[]models.PackageVulns](t, "fixtures-go/input.json")
	gvcResByVulnID := testfixture.LoadJSON[map[string][]*govulncheck.Finding](t, "fixtures-go/govulncheckinput.json")
	vulnsByID := testfixture.LoadJSON[map[string]models.Vulnerability](t, "fixtures-go/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testsnapshot.New().MatchJSON(t, pkgs)
}

func Test_matchEmptyAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testfixture.LoadJSON[[]models.PackageVulns](t, "fixtures-go/input-no-call-data.json")
	// When there is no ecosystem specific data, govulncheck will return no results
	gvcResByVulnID := map[string][]*govulncheck.Finding{}
	vulnsByID := testfixture.LoadJSON[map[string]models.Vulnerability](t, "fixtures-go/vulnbyid-no-call-data.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testsnapshot.New().MatchJSON(t, pkgs)
}
