package sourceanalysis

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func TestPackageVulnsWithCalledInfo(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "fixtures/input.json")
	osvToFinding := testutility.LoadJSONFixture[map[string]*govulncheck.Finding](t, "fixtures/govulncheckinput.json")
	vulnsByID := testutility.LoadJSONFixture[map[string]models.Vulnerability](t, "fixtures/vulnbyid.json")

	got := packageVulnsWithCalledInfo(pkgs, osvToFinding, vulnsByID)
	testutility.AssertMatchFixtureJSON(t, "fixtures/output.json", got)
}

// TestGoAnalysis runs goAnalysis on the module in testdata/module,
//
// Expected results:
//
//	https://pkg.go.dev/vuln/GO-2021-0054 // github.com/tidwall/gjson (unaffected)
//	https://pkg.go.dev/vuln/GO-2021-0113 // golang.org/x/text/language (affected)
func TestGoAnalysis(t *testing.T) {
	t.Parallel()

	// vulnGo0054 represents https://pkg.go.dev/vuln/GO-2021-0054, which affects
	// github.com/tidwall/gjson.
	var (
		vulnGo0054 = models.Vulnerability{
			SchemaVersion: "1.3.1",
			ID:            "GO-2021-0054",
			Aliases: []string{
				"CVE-2020-36067",
				"GHSA-p64j-r5f4-pwwx",
			},
			Affected: []models.Affected{
				{
					Package: models.Package{
						Name:      "github.com/tidwall/gjson",
						Ecosystem: "Go",
					},
					Ranges: []models.Range{
						{
							Type: models.RangeSemVer,
							Events: []models.Event{
								{
									Introduced: "0",
									Fixed:      "1.6.6",
								},
							},
						},
					},
					EcosystemSpecific: map[string]interface{}{
						"imports": []map[string]interface{}{
							{
								"path": "github.com/tidwall/gjson",
								"symbols": []string{
									"Result.ForEach",
									"unwrap",
								},
							},
						},
					},
				},
			},
		}

		// vulnGo0113 represents https://pkg.go.dev/vuln/GO-2021-0113, which affects
		// golang.org/x/text/language.
		vulnGo0113 = models.Vulnerability{
			SchemaVersion: "1.3.1",
			ID:            "GO-2021-0113",
			Aliases:       []string{},
			Affected: []models.Affected{
				{
					Package: models.Package{
						Name:      "golang.org/x/text",
						Ecosystem: "Go",
					},
					Ranges: []models.Range{
						{
							Type: models.RangeSemVer,
							Events: []models.Event{
								{
									Introduced: "0",
									Fixed:      "v0.3.7",
								},
							},
						},
					},
					EcosystemSpecific: map[string]interface{}{
						"imports": []map[string]interface{}{
							{
								"path": "golang.org/x/text/language",
								"symbols": []string{
									"MatchStrings",
									"MustParse",
									"Parse",
									"ParseAcceptLanguage",
								},
							},
						},
					},
				},
			},
		}
	)

	var (
		// gjson represents the module github.com/tidwall/gjson at a vulnerable
		// version. However, the vulnerability is not called.
		gjson = models.PackageVulns{
			Package: models.PackageInfo{
				Name:      "github.com/tidwall/gjson",
				Version:   "1.6.0", // this is before the fixed version
				Ecosystem: "Go",
			},
			Vulnerabilities: []models.Vulnerability{vulnGo0054},
			Groups: []models.GroupInfo{
				{
					IDs: []string{"GO-2021-0054"},
				},
			},
		}

		// x/text represents the module golang.org/x/text at a vulnerable
		// version. The vulnerability is called by the module at testdata/module.
		xtext = models.PackageVulns{
			Package: models.PackageInfo{
				Name:      "golang.org/x/text",
				Version:   "0.3.5", // this is before the fixed version
				Ecosystem: "Go",
			},
			Vulnerabilities: []models.Vulnerability{vulnGo0113},
			Groups: []models.GroupInfo{
				{
					IDs: []string{"GO-2021-0113"},
				},
			},
		}
	)

	pkgs := []models.PackageVulns{gjson, xtext}
	got, err := goAnalysis("testdata/module", pkgs)
	if err != nil {
		t.Fatal(err)
	}

	gjson2 := gjson
	gjson2.Groups = nil
	gjson2.Groups = []models.GroupInfo{
		{
			IDs: []string{"GO-2021-0054"},
			ExperimentalAnalysis: map[string]*models.AnalysisInfo{
				"GO-2021-0054": {Called: false},
			},
		},
	}
	xtext2 := xtext
	xtext2.Groups = nil
	xtext2.Groups = []models.GroupInfo{
		{
			IDs: []string{"GO-2021-0113"},
			ExperimentalAnalysis: map[string]*models.AnalysisInfo{
				"GO-2021-0113": {Called: true},
			},
		},
	}

	want := []models.PackageVulns{gjson2, xtext2}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
