package models_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestFlatten(t *testing.T) {
	t.Parallel()

	packageInfoComparer := cmp.Comparer(func(a, b models.PackageInfo) bool {
		if cmp.Equal(a, b, cmp.AllowUnexported(models.PackageInfo{})) {
			aExtractor := a.GetExtractor()
			bExtractor := b.GetExtractor()

			if aExtractor == nil && bExtractor == nil {
				return true
			}

			if aExtractor == nil || bExtractor == nil {
				return false
			}

			if aExtractor.Name() != bExtractor.Name() {
				return false
			}

			if aExtractor.Version() != bExtractor.Version() {
				return false
			}

			return cmp.Equal(aExtractor.Requirements(), bExtractor.Requirements())
		}

		return true

		return cmp.Equal(a, b, cmp.AllowUnexported(models.PackageInfo{}))
		return false
		return a.Name == b.Name && a.Version == b.Version
	})

	// Test case 1: When there are no vulnerabilities
	vulns := models.VulnerabilityResults{Results: []models.PackageSource{}}
	expectedFlattened := []models.VulnerabilityFlattened{}
	flattened := vulns.Flatten()
	if diff := cmp.Diff(expectedFlattened, flattened, packageInfoComparer); diff != "" {
		t.Errorf("Flatten() returned unexpected result (-want +got):\n%s", diff)
	}

	// Test case 2: When there are vulnerabilities
	group := models.GroupInfo{IDs: []string{"CVE-2021-1234"}}
	pkg := models.PackageVulns{
		Package:   models.PackageInfo{Name: "package"},
		DepGroups: []string{"dev"},
		Groups:    []models.GroupInfo{group},
		Vulnerabilities: []osvschema.Vulnerability{
			{
				ID: "CVE-2021-1234",
				Severity: []osvschema.Severity{
					{
						Type:  osvschema.SeverityType("high"),
						Score: "1",
					},
				},
			},
		},
		Licenses: []models.License{models.License("MIT")},
	}
	source := models.PackageSource{Source: models.SourceInfo{Path: "package"}, Packages: []models.PackageVulns{pkg}}
	vulns = models.VulnerabilityResults{Results: []models.PackageSource{source}}
	expectedFlattened = []models.VulnerabilityFlattened{
		{
			Source:        source.Source,
			Package:       pkg.Package,
			DepGroups:     []string{"dev"},
			Vulnerability: pkg.Vulnerabilities[0],
			GroupInfo:     group,
		},
	}
	flattened = vulns.Flatten()
	if diff := cmp.Diff(expectedFlattened, flattened, packageInfoComparer); diff != "" {
		t.Errorf("Flatten() returned unexpected result (-want +got):\n%s", diff)
	}

	// Test case 3: When there are no vulnerabilities and license violations
	group = models.GroupInfo{IDs: []string{"CVE-2021-1234"}}
	pkg = models.PackageVulns{
		Package:           models.PackageInfo{Name: "package"},
		DepGroups:         []string{"dev"},
		Groups:            []models.GroupInfo{group},
		Licenses:          []models.License{"MIT"},
		LicenseViolations: []models.License{"MIT"},
	}
	source = models.PackageSource{Source: models.SourceInfo{Path: "package"}, Packages: []models.PackageVulns{pkg}}
	vulns = models.VulnerabilityResults{Results: []models.PackageSource{source}}
	expectedFlattened = []models.VulnerabilityFlattened{
		{
			Source:            source.Source,
			Package:           pkg.Package,
			DepGroups:         []string{"dev"},
			Licenses:          []models.License{"MIT"},
			LicenseViolations: []models.License{"MIT"},
		},
	}
	flattened = vulns.Flatten()
	if diff := cmp.Diff(expectedFlattened, flattened, packageInfoComparer); diff != "" {
		t.Errorf("Flatten() returned unexpected result (-want +got):\n%s", diff)
	}

	// Test case 4: When there are vulnerabilities and license violations
	group = models.GroupInfo{IDs: []string{"CVE-2021-1234"}}
	pkg = models.PackageVulns{
		Package:   models.PackageInfo{Name: "package"},
		DepGroups: []string{"dev"},
		Groups:    []models.GroupInfo{group},
		Vulnerabilities: []osvschema.Vulnerability{
			{
				ID: "CVE-2021-1234",
				Severity: []osvschema.Severity{
					{
						Type:  "high",
						Score: "1",
					},
				},
			},
		},
		Licenses:          []models.License{"MIT"},
		LicenseViolations: []models.License{"MIT"},
	}
	source = models.PackageSource{Source: models.SourceInfo{Path: "package"}, Packages: []models.PackageVulns{pkg}}
	vulns = models.VulnerabilityResults{Results: []models.PackageSource{source}}
	expectedFlattened = []models.VulnerabilityFlattened{
		{
			Source:        source.Source,
			Package:       pkg.Package,
			DepGroups:     []string{"dev"},
			Vulnerability: pkg.Vulnerabilities[0],
			GroupInfo:     group,
		},
		{
			Source:            source.Source,
			Package:           pkg.Package,
			DepGroups:         []string{"dev"},
			Licenses:          []models.License{"MIT"},
			LicenseViolations: []models.License{"MIT"},
		},
	}
	flattened = vulns.Flatten()
	if diff := cmp.Diff(expectedFlattened, flattened, packageInfoComparer); diff != "" {
		t.Errorf("Flatten() returned unexpected result (-want +got):\n%s", diff)
	}

	// todo: we should handle the extractor field...
}
