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

	pkgs := testfixture.LoadJSON[[]models.PackageVulns](t, testfixture.New("fixtures-go/input.json", map[string]string{}))
	gvcResByVulnID := testfixture.LoadJSON[map[string][]*govulncheck.Finding](t, testfixture.New("fixtures-go/govulncheckinput.json", map[string]string{}))
	vulnsByID := testfixture.LoadJSON[map[string]models.Vulnerability](t, testfixture.New("fixtures-go/vulnbyid.json", map[string]string{}))

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testsnapshot.New(map[string]string{}).MatchJSON(t, pkgs)
}

func Test_matchEmptyAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testfixture.LoadJSON[[]models.PackageVulns](t, testfixture.New("fixtures-go/input-no-call-data.json", map[string]string{}))
	// When there is no ecosystem specific data, govulncheck will return no results
	gvcResByVulnID := map[string][]*govulncheck.Finding{}
	vulnsByID := testfixture.LoadJSON[map[string]models.Vulnerability](t, testfixture.New("fixtures-go/vulnbyid-no-call-data.json", map[string]string{}))

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testsnapshot.New(map[string]string{}).MatchJSON(t, pkgs)
}
