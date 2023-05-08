package sourceanalysis

import (
	"testing"

	"github.com/google/osv-scanner/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "fixtures/input.json")
	osvToFinding := testutility.LoadJSONFixture[map[string]*govulncheck.Finding](t, "fixtures/govulncheckinput.json")
	vulnsByID := testutility.LoadJSONFixture[map[string]models.Vulnerability](t, "fixtures/vulnbyid.json")

	want := matchAnalysisWithPackageVulns(pkgs, osvToFinding, vulnsByID)
	testutility.AssertMatchFixtureJSON(t, "fixtures/output.json", want)
}
