package models

import "testing"

func TestFlatten(t *testing.T) {
	// Test case 1: When there are no vulnerabilities
	vulns := VulnerabilityResults{Results: []PackageSource{}}
	flattened := vulns.Flatten()
	if len(flattened) != 0 {
		t.Errorf("Flatten() returned %d results, expected 0", len(flattened))
	}

	// Test case 2: When there are vulnerabilities
	group := GroupInfo{IDs: []string{"CVE-2021-1234"}}
	pkg := PackageVulns{
		Package: PackageInfo{Name: "package"},
		Groups:  []GroupInfo{group},
		Vulnerabilities: []Vulnerability{
			{
				ID: "CVE-2021-1234",
				Severity: []Severity{
					{
						Type:  SeverityType("high"),
						Score: "1",
					},
				},
			},
		},
	}
	source := PackageSource{Source: SourceInfo{Path: "package"}, Packages: []PackageVulns{pkg}}
	vulns = VulnerabilityResults{Results: []PackageSource{source}}
	flattened = vulns.Flatten()
	if len(flattened) != 1 {
		t.Errorf("Flatten() returned %d results, expected 1", len(flattened))
	}
	if flattened[0].Source != source.Source {
		t.Errorf("Flatten() returned source '%s', expected '%s'", flattened[0].Source, source.Source)
	}
	if flattened[0].Package != pkg.Package {
		t.Errorf("Flatten() returned package '%s', expected '%s'", flattened[0].Package, pkg.Package)
	}
	if flattened[0].Vulnerability.ID != pkg.Vulnerabilities[0].ID {
		t.Errorf("Flatten() returned vulnerability ID '%s', expected '%s'", flattened[0].Vulnerability.ID, pkg.Vulnerabilities[0].ID)
	}
	if flattened[0].GroupInfo.IDs[0] != group.IDs[0] {
		t.Errorf("Flatten() returned group ID '%s', expected '%s'", flattened[0].GroupInfo.IDs[0], group.IDs[0])
	}
}
