package sourceanalysis

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "testdata/json/input.json")
	gvcResByVulnID := testutility.LoadJSONFixture[map[string][]*govulncheck.Finding](t, "testdata/json/govulncheckinput.json")
	vulnsByID := testutility.LoadVulnMapFixture(t, "testdata/json/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
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

// Test_matchAnalysisWithPackageVulns_calledDominatesUncalled checks that a
// vulnerability with any called finding is marked as called regardless of the
// order the findings are aggregated in (issue #3162).
func Test_matchAnalysisWithPackageVulns_calledDominatesUncalled(t *testing.T) {
	t.Parallel()

	const vulnID = "GO-2021-0053"
	const modulePath = "github.com/gogo/protobuf"

	calledFinding := &govulncheck.Finding{
		OSV: vulnID,
		Trace: []*govulncheck.Frame{{
			Module:   modulePath,
			Version:  "v1.3.1",
			Function: "RegisterEnum",
		}},
	}
	uncalledFinding := &govulncheck.Finding{
		OSV: vulnID,
		Trace: []*govulncheck.Frame{{
			Module:  modulePath,
			Version: "v1.3.1",
		}},
	}

	tests := []struct {
		name       string
		findings   []*govulncheck.Finding
		wantCalled bool
	}{
		{
			name:       "called finding first, uncalled finding last",
			findings:   []*govulncheck.Finding{calledFinding, uncalledFinding},
			wantCalled: true,
		},
		{
			name:       "uncalled finding first, called finding last",
			findings:   []*govulncheck.Finding{uncalledFinding, calledFinding},
			wantCalled: true,
		},
		{
			name:       "all findings uncalled",
			findings:   []*govulncheck.Finding{uncalledFinding, uncalledFinding},
			wantCalled: false,
		},
	}

	vulnsByID := map[string]*osvschema.Vulnerability{
		vulnID: {
			Id: vulnID,
			Affected: []*osvschema.Affected{{
				Package: &osvschema.Package{
					Ecosystem: "Go",
					Name:      modulePath,
				},
				EcosystemSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"imports": structpb.NewStructValue(&structpb.Struct{
							Fields: map[string]*structpb.Value{
								"0": structpb.NewStringValue("github.com/gogo/protobuf/proto"),
							},
						}),
					},
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgs := []models.PackageVulns{{
				Package: models.PackageInfo{
					Name:      modulePath,
					Version:   "1.3.1",
					Ecosystem: "Go",
				},
				Groups: []models.GroupInfo{{
					IDs:     []string{vulnID},
					Aliases: []string{vulnID},
				}},
			}}

			matchAnalysisWithPackageVulns(pkgs, map[string][]*govulncheck.Finding{vulnID: tt.findings}, vulnsByID)

			got := pkgs[0].Groups[0].ExperimentalAnalysis[vulnID].Called
			if got != tt.wantCalled {
				t.Errorf("ExperimentalAnalysis[%q].Called = %v, want %v", vulnID, got, tt.wantCalled)
			}
		})
	}
}
