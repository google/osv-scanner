package models_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestFlatten(t *testing.T) {
	t.Parallel()
	// Test case 1: When there are no vulnerabilities
	vulns := models.VulnerabilityResults{Results: []models.PackageSource{}}
	expectedFlattened := []models.VulnerabilityFlattened{}
	flattened := vulns.Flatten()
	if diff := cmp.Diff(expectedFlattened, flattened, protocmp.Transform()); diff != "" {
		t.Errorf("Flatten() returned unexpected result (-want +got):\n%s", diff)
	}

	// Test case 2: When there are vulnerabilities
	group := models.GroupInfo{IDs: []string{"CVE-2021-1234"}}
	pkg := models.PackageVulns{
		Package:   models.PackageInfo{Name: "package"},
		DepGroups: []string{"dev"},
		Groups:    []models.GroupInfo{group},
		Vulnerabilities: []*osvschema.Vulnerability{
			{
				Id: "CVE-2021-1234",
				Severity: []*osvschema.Severity{
					{
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
	if diff := cmp.Diff(expectedFlattened, flattened, protocmp.Transform()); diff != "" {
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
	if diff := cmp.Diff(expectedFlattened, flattened, protocmp.Transform()); diff != "" {
		t.Errorf("Flatten() returned unexpected result (-want +got):\n%s", diff)
	}

	// Test case 4: When there are vulnerabilities and license violations
	group = models.GroupInfo{IDs: []string{"CVE-2021-1234"}}
	pkg = models.PackageVulns{
		Package:   models.PackageInfo{Name: "package"},
		DepGroups: []string{"dev"},
		Groups:    []models.GroupInfo{group},
		Vulnerabilities: []*osvschema.Vulnerability{
			{
				Id: "CVE-2021-1234",
				Severity: []*osvschema.Severity{
					{
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
	if diff := cmp.Diff(expectedFlattened, flattened, protocmp.Transform()); diff != "" {
		t.Errorf("Flatten() returned unexpected result (-want +got):\n%s", diff)
	}
}
