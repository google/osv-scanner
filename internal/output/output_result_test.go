package output_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestPrintOutputResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestBuildResults_ExactEcosystemGrouping(t *testing.T) {
	t.Parallel()

	packageWithVuln := func(name, ecosystem, vulnID string) models.PackageVulns {
		return models.PackageVulns{
			Package: models.PackageInfo{
				Name:      name,
				Version:   "1.0.0",
				Ecosystem: ecosystem,
			},
			Vulnerabilities: []*osvschema.Vulnerability{{Id: vulnID}},
			Groups:          []models.GroupInfo{{IDs: []string{vulnID}}},
		}
	}

	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{{
			Source: models.SourceInfo{Path: "mixed.sbom", Type: models.SourceTypeSBOM},
			Packages: []models.PackageVulns{
				packageWithVuln("base-package", "Alpine", "OSV-BASE"),
				packageWithVuln("versioned-package", "Alpine:v3.18", "OSV-VERSIONED"),
			},
		}},
	}

	got := make(map[string][]string)
	for _, ecosystem := range output.BuildResults(vulnResult).Ecosystems {
		for _, source := range ecosystem.Sources {
			for _, pkg := range source.Packages {
				got[ecosystem.Name] = append(got[ecosystem.Name], pkg.Name)
			}
		}
	}
	want := map[string][]string{
		"Alpine":       {"base-package"},
		"Alpine:v3.18": {"versioned-package"},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("BuildResults() ecosystem packages mismatch (-want +got):\n%s", diff)
	}
}
