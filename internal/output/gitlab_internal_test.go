package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/output/gitlab"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/xeipuuv/gojsonschema"
)

// gitlabSchemaVersion documents the release of the GitLab Security Report Schemas
// that the vendored schemas under testdata/schemas were copied from. It should match
// the report version we generate (see gitlab/version.go). To refresh the vendored
// schemas, download the matching files from:
//
//	https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/<gitlabSchemaVersion>/dist/<schemaFile>
const gitlabSchemaVersion = "v15.2.4"

// loadGitLabSchema loads a vendored GitLab schema from testdata so validation stays
// hermetic (no network access at test time).
func loadGitLabSchema(t *testing.T, schemaFile string) gojsonschema.JSONLoader {
	t.Helper()

	schemaPath := filepath.Join("gitlab", "testdata", "schemas", schemaFile)
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed to read vendored schema %q: %v", schemaPath, err)
	}

	return gojsonschema.NewBytesLoader(schemaBytes)
}

func validateGitLabReport(t *testing.T, schemaLoader gojsonschema.JSONLoader, report any) {
	t.Helper()

	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}

	validateGitLabReportBytes(t, schemaLoader, reportJSON)
}

// validateGitLabReportBytes validates already-encoded report JSON against a GitLab schema.
func validateGitLabReportBytes(t *testing.T, schemaLoader gojsonschema.JSONLoader, reportJSON []byte) {
	t.Helper()

	documentLoader := gojsonschema.NewBytesLoader(reportJSON)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		t.Fatalf("validation error: %v", err)
	}

	if !result.Valid() {
		t.Errorf("report does not validate against GitLab schema:")
		for _, desc := range result.Errors() {
			t.Errorf("  - %s", desc)
		}
		t.Logf("Generated report:\n%s", string(reportJSON))
	}
}

func TestDetermineScanType(t *testing.T) {
	tests := []struct {
		name     string
		input    *models.VulnerabilityResults
		expected gitlab.Category
	}{
		{
			name:     "container scanning",
			input:    &models.VulnerabilityResults{ImageMetadata: &models.ImageMetadata{}},
			expected: gitlab.CategoryContainerScanning,
		},
		{
			name:     "dependency scanning",
			input:    &models.VulnerabilityResults{},
			expected: gitlab.CategoryDependencyScanning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineScanType(tt.input)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBuildIdentifiers(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Id:      "CVE-2023-1234",
		Aliases: []string{"GHSA-xxxx-yyyy-zzzz", "invalid-id"},
	}

	identifiers := buildIdentifiers(vuln)

	if len(identifiers) != 2 {
		t.Errorf("expected 2 identifiers, got %d", len(identifiers))
	}

	if identifiers[0].Type != gitlab.IdentifierTypeCVE {
		t.Errorf("expected CVE type, got %v", identifiers[0].Type)
	}

	if identifiers[1].Type != gitlab.IdentifierTypeGHSA {
		t.Errorf("expected GHSA type, got %v", identifiers[1].Type)
	}
}

func TestBuildIdentifiers_AllTypes(t *testing.T) {
	tests := []struct {
		id           string
		expectedType gitlab.IdentifierType
	}{
		{"CVE-2023-1234", gitlab.IdentifierTypeCVE},
		{"CWE-79", gitlab.IdentifierTypeCWE},
		{"GHSA-xxxx-yyyy-zzzz", gitlab.IdentifierTypeGHSA},
		{"GLAM-12345", gitlab.IdentifierTypeGLAM},
		{"MAL-2023-1234", gitlab.IdentifierTypeMAL},
		{"RHSA-2023:1234", gitlab.IdentifierTypeRHSA},
		{"USN-1234-1", gitlab.IdentifierTypeUSN},
		{"ELSA-2023-1234", gitlab.IdentifierTypeELSA},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{Id: tt.id}
			identifiers := buildIdentifiers(vuln)

			if len(identifiers) != 1 {
				t.Errorf("expected 1 identifier for %s, got %d", tt.id, len(identifiers))
				return
			}
			if identifiers[0].Type != tt.expectedType {
				t.Errorf("expected type %v for %s, got %v", tt.expectedType, tt.id, identifiers[0].Type)
			}
		})
	}
}

func TestBuildCVSSRatings(t *testing.T) {
	severities := []*osvschema.Severity{
		{Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Score: "7.5"},
	}

	ratings := buildCVSSRatings(severities)

	if len(ratings) != 2 {
		t.Errorf("expected 2 ratings, got %d", len(ratings))
	}

	for _, rating := range ratings {
		if rating.Vendor != "unknown" {
			t.Errorf("expected vendor 'unknown', got %v", rating.Vendor)
		}
	}
}

func TestBuildLinks(t *testing.T) {
	references := []*osvschema.Reference{
		{Url: "https://example.com/vuln1"},
		{Url: "https://example.com/vuln2"},
	}

	links := buildLinks(references)

	if len(links) != 2 {
		t.Errorf("expected 2 links, got %d", len(links))
	}

	if links[0].URL != "https://example.com/vuln1" {
		t.Errorf("expected first URL to be https://example.com/vuln1, got %v", links[0].URL)
	}
}

func TestBuildLocation(t *testing.T) {
	packageItem := models.PackageVulns{
		Package: models.PackageInfo{Name: "test-package", Version: "1.0.0"},
	}
	result := models.PackageSource{Source: models.SourceInfo{Path: "/test/path", Type: models.SourceTypeProjectPackage}}

	t.Run("dependency scanning", func(t *testing.T) {
		location := buildLocation(packageItem, result, &models.VulnerabilityResults{}, gitlab.CategoryDependencyScanning)

		if location.File != "/test/path" {
			t.Errorf("expected file path '/test/path', got %v", location.File)
		}
		if location.Dependency.Package.Name != "test-package" {
			t.Errorf("expected package name 'test-package', got %v", location.Dependency.Package.Name)
		}
		if len(location.Files) != 1 {
			t.Errorf("expected 1 file, got %d", len(location.Files))
		} else {
			if location.Files[0].Path != "/test/path" {
				t.Errorf("expected file path '/test/path', got %v", location.Files[0].Path)
			}
			if location.Files[0].Type != gitlab.FileTypeLockfile {
				t.Errorf("expected file type 'lockfile', got %v", location.Files[0].Type)
			}
		}
	})

	t.Run("container scanning", func(t *testing.T) {
		vulnResult := &models.VulnerabilityResults{
			ImageMetadata: &models.ImageMetadata{OS: "ubuntu:20.04"},
		}
		location := buildLocation(packageItem, result, vulnResult, gitlab.CategoryContainerScanning)

		if location.Image != "/test/path" {
			t.Errorf("expected image '/test/path', got %v", location.Image)
		}
		if location.OperatingSystem != "ubuntu:20.04" {
			t.Errorf("expected OS 'ubuntu:20.04', got %v", location.OperatingSystem)
		}
		if len(location.Files) != 0 {
			t.Errorf("expected no files for container scanning, got %d", len(location.Files))
		}
	})
}

func TestPrintGitLabResults(t *testing.T) {
	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: "/test/package.json"},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{Name: "test-pkg", Version: "1.0.0"},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id:      "CVE-2023-1234",
								Summary: "Short summary of the vulnerability",
								Details: "Detailed description of the vulnerability",
								Severity: []*osvschema.Severity{
									{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
								},
								References: []*osvschema.Reference{
									{Url: "https://example.com/vuln"},
								},
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := PrintGitLabResults(vulnResult, &buf)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report gitlab.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(report.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(report.Vulnerabilities))
		return
	}

	vuln := report.Vulnerabilities[0]
	if vuln.Name != "CVE-2023-1234" {
		t.Errorf("expected vulnerability name 'CVE-2023-1234', got %v", vuln.Name)
	}

	if vuln.Message != "Short summary of the vulnerability" {
		t.Errorf("expected Message to be summary, got %v", vuln.Message)
	}

	if vuln.Description != "Detailed description of the vulnerability" {
		t.Errorf("expected Description to be details, got %v", vuln.Description)
	}

	if report.Scan.Type != gitlab.CategoryDependencyScanning {
		t.Errorf("expected dependency scanning type, got %v", report.Scan.Type)
	}
}

func TestPrintGitLabResults_VulnerabilityWithoutCVSS(t *testing.T) {
	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: "/test/package.json"},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{Name: "test-pkg", Version: "1.0.0"},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id:      "GHSA-xxxx-yyyy-zzzz",
								Details: "Vulnerability without CVSS score",
								// No Severity field - should not be skipped
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := PrintGitLabResults(vulnResult, &buf)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report gitlab.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(report.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability (should not be skipped), got %d", len(report.Vulnerabilities))
		return
	}

	vuln := report.Vulnerabilities[0]
	if vuln.Severity != gitlab.SeverityLevelUnknown {
		t.Errorf("expected Unknown severity for vulnerability without CVSS, got %v", vuln.Severity)
	}
}

func TestPrintGitLabResults_ContainerScanning(t *testing.T) {
	vulnResult := &models.VulnerabilityResults{
		ImageMetadata: &models.ImageMetadata{OS: "debian:11"},
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: "nginx:1.21"},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{Name: "openssl", Version: "1.1.1k-1"},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id:      "CVE-2023-0286",
								Summary: "OpenSSL vulnerability",
								Details: "There is a type confusion vulnerability in OpenSSL",
								Severity: []*osvschema.Severity{
									{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H"},
								},
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := PrintGitLabResults(vulnResult, &buf)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report gitlab.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if report.Scan.Type != gitlab.CategoryContainerScanning {
		t.Errorf("expected container_scanning type, got %v", report.Scan.Type)
	}

	if len(report.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(report.Vulnerabilities))
		return
	}

	vuln := report.Vulnerabilities[0]
	if vuln.Location.Image != "nginx:1.21" {
		t.Errorf("expected image 'nginx:1.21', got %v", vuln.Location.Image)
	}
	if vuln.Location.OperatingSystem != "debian:11" {
		t.Errorf("expected OS 'debian:11', got %v", vuln.Location.OperatingSystem)
	}
	if vuln.Location.File != "" {
		t.Errorf("expected no file for container scanning, got %v", vuln.Location.File)
	}
}

func TestPrintGitLabResults_EmptyResults(t *testing.T) {
	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{},
	}

	var buf bytes.Buffer
	err := PrintGitLabResults(vulnResult, &buf)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report gitlab.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(report.Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities for empty results, got %d", len(report.Vulnerabilities))
	}

	// Should still have valid scan metadata
	if report.Scan.Analyzer.ID != "osv-scanner" {
		t.Errorf("expected analyzer ID 'osv-scanner', got %v", report.Scan.Analyzer.ID)
	}
}

func TestPrintGitLabResults_MultipleVulnerabilities(t *testing.T) {
	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: "/app/package.json", Type: models.SourceTypeProjectPackage},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{Name: "lodash", Version: "4.17.20"},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id:      "CVE-2021-23337",
								Summary: "Command Injection in lodash",
								Severity: []*osvschema.Severity{
									{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},
								},
							},
							{
								Id:      "CVE-2020-8203",
								Summary: "Prototype Pollution in lodash",
								Severity: []*osvschema.Severity{
									{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"},
								},
							},
						},
					},
					{
						Package: models.PackageInfo{Name: "axios", Version: "0.21.0"},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id:      "CVE-2021-3749",
								Summary: "Server-Side Request Forgery in axios",
								Severity: []*osvschema.Severity{
									{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
								},
							},
						},
					},
				},
			},
			{
				Source: models.SourceInfo{Path: "/lib/requirements.txt", Type: models.SourceTypeProjectPackage},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{Name: "requests", Version: "2.25.0"},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id:      "CVE-2023-32681",
								Summary: "Unintended leak of Proxy-Authorization header in requests",
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := PrintGitLabResults(vulnResult, &buf)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report gitlab.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(report.Vulnerabilities) != 4 {
		t.Errorf("expected 4 vulnerabilities, got %d", len(report.Vulnerabilities))
	}

	// Verify version is set
	if report.Version.String() != gitlab.CurrentVersion().String() {
		t.Errorf("expected version %s, got %s", gitlab.CurrentVersion().String(), report.Version.String())
	}
}

func TestPrintGitLabResults_SeverityLevels(t *testing.T) {
	tests := []struct {
		cvssVector    string
		expectedLevel gitlab.SeverityLevel
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", gitlab.SeverityLevelCritical}, // 10.0
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", gitlab.SeverityLevelCritical}, // 9.8
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", gitlab.SeverityLevelHigh},     // 7.5
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", gitlab.SeverityLevelMedium},   // 5.4
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", gitlab.SeverityLevelLow},      // 3.3
	}

	for _, tt := range tests {
		t.Run(tt.expectedLevel.String(), func(t *testing.T) {
			vulnResult := &models.VulnerabilityResults{
				Results: []models.PackageSource{
					{
						Source: models.SourceInfo{Path: "/test/package.json"},
						Packages: []models.PackageVulns{
							{
								Package: models.PackageInfo{Name: "test-pkg", Version: "1.0.0"},
								Vulnerabilities: []*osvschema.Vulnerability{
									{
										Id: "CVE-2023-0001",
										Severity: []*osvschema.Severity{
											{Type: osvschema.Severity_CVSS_V3, Score: tt.cvssVector},
										},
									},
								},
							},
						},
					},
				},
			}

			var buf bytes.Buffer
			err := PrintGitLabResults(vulnResult, &buf)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var report gitlab.Report
			if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
				t.Fatalf("failed to unmarshal JSON: %v", err)
			}

			if len(report.Vulnerabilities) != 1 {
				t.Fatalf("expected 1 vulnerability, got %d", len(report.Vulnerabilities))
			}

			if report.Vulnerabilities[0].Severity != tt.expectedLevel {
				t.Errorf("expected severity %v, got %v", tt.expectedLevel, report.Vulnerabilities[0].Severity)
			}
		})
	}
}

// Schema validation tests

func TestReport_ValidatesAgainstGitLabSchema(t *testing.T) {
	schemaLoader := loadGitLabSchema(t, "dependency-scanning-report-format.json")

	// Create a sample report
	report := gitlab.Report{
		Version: gitlab.CurrentVersion(),
		Vulnerabilities: []gitlab.Vulnerability{
			{
				Name:        "CVE-2023-1234",
				Message:     "Test vulnerability message",
				Description: "A detailed description of the vulnerability",
				Severity:    gitlab.SeverityLevelHigh,
				Solution:    "Upgrade to version 2.0.0",
				Location: gitlab.Location{
					File: "/app/package.json",
					Dependency: &gitlab.Dependency{
						Package: gitlab.Package{Name: "lodash"},
						Version: "4.17.20",
					},
					Files: []gitlab.File{
						{
							Path: "/app/package.json",
							Type: gitlab.FileTypeLockfile,
						},
					},
				},
				Identifiers: []gitlab.Identifier{
					{
						Type:  gitlab.IdentifierTypeCVE,
						Name:  "CVE-2023-1234",
						Value: "CVE-2023-1234",
						URL:   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234",
					},
					{
						Type:  gitlab.IdentifierTypeGHSA,
						Name:  "GHSA-xxxx-yyyy-zzzz",
						Value: "GHSA-xxxx-yyyy-zzzz",
						URL:   "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
					},
				},
				CVSSRatings: []gitlab.CVSSRating{
					{
						Vendor: "NVD",
						Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
				},
				Links: []gitlab.Link{
					{URL: "https://example.com/advisory"},
				},
			},
		},
		Scan: gitlab.Scan{
			Analyzer: gitlab.AnalyzerDetails{
				ID:      "osv-scanner",
				Name:    "osv-scanner",
				URL:     "https://github.com/google/osv-scanner",
				Vendor:  gitlab.Vendor{Name: "Google"},
				Version: "2.0.0",
			},
			Scanner: gitlab.AnalyzerDetails{
				ID:      "osv-scanner",
				Name:    "osv-scanner",
				URL:     "https://github.com/google/osv-scanner",
				Vendor:  gitlab.Vendor{Name: "Google"},
				Version: "2.0.0",
			},
			Type:      gitlab.CategoryDependencyScanning,
			Status:    gitlab.StatusSuccess,
			StartTime: "2025-01-01T12:00:00",
			EndTime:   "2025-01-01T12:00:01",
		},
	}

	validateGitLabReport(t, schemaLoader, report)
}

// sampleVulnResults returns a representative VulnerabilityResults that exercises the
// fields the GitLab report builder reads (ids, aliases, severities, references), so the
// report validated against the schema is produced by the real PrintGitLabResults code
// path rather than a hand-maintained fixture that can drift from the output.
func sampleVulnResults() *models.VulnerabilityResults {
	return &models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: "/app/package.json", Type: models.SourceTypeProjectPackage},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{Name: "lodash", Version: "4.17.20"},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id:      "CVE-2021-23337",
								Summary: "Command Injection in lodash",
								Details: "lodash versions prior to 4.17.21 are vulnerable to command injection.",
								Aliases: []string{"GHSA-35jh-r3h4-6jhm"},
								Severity: []*osvschema.Severity{
									{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},
								},
								References: []*osvschema.Reference{
									{Url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"},
								},
							},
						},
					},
				},
			},
			{
				Source: models.SourceInfo{Path: "/lib/requirements.txt", Type: models.SourceTypeProjectPackage},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{Name: "requests", Version: "2.25.0"},
						Vulnerabilities: []*osvschema.Vulnerability{
							{
								Id:      "CVE-2023-32681",
								Summary: "Unintended leak of Proxy-Authorization header in requests",
							},
						},
					},
				},
			},
		},
	}
}

func TestDependencyScanReport_ValidatesAgainstGitLabSchema(t *testing.T) {
	schemaLoader := loadGitLabSchema(t, "dependency-scanning-report-format.json")

	var buf bytes.Buffer
	if err := PrintGitLabResults(sampleVulnResults(), &buf); err != nil {
		t.Fatalf("unexpected error generating report: %v", err)
	}

	validateGitLabReportBytes(t, schemaLoader, buf.Bytes())
}

func TestContainerScanReport_ValidatesAgainstGitLabSchema(t *testing.T) {
	schemaLoader := loadGitLabSchema(t, "container-scanning-report-format.json")

	// ImageMetadata being set switches PrintGitLabResults to the container-scanning path.
	vulnResult := sampleVulnResults()
	vulnResult.ImageMetadata = &models.ImageMetadata{OS: "debian:12"}

	var buf bytes.Buffer
	if err := PrintGitLabResults(vulnResult, &buf); err != nil {
		t.Fatalf("unexpected error generating report: %v", err)
	}

	validateGitLabReportBytes(t, schemaLoader, buf.Bytes())
}

func TestReport_MinimalValid(t *testing.T) {
	schemaLoader := loadGitLabSchema(t, "dependency-scanning-report-format.json")

	// Create a minimal valid report (empty vulnerabilities)
	report := gitlab.Report{
		Version:         gitlab.CurrentVersion(),
		Vulnerabilities: []gitlab.Vulnerability{},
		Scan: gitlab.Scan{
			Analyzer: gitlab.AnalyzerDetails{
				ID:      "osv-scanner",
				Name:    "osv-scanner",
				URL:     "https://github.com/google/osv-scanner",
				Vendor:  gitlab.Vendor{Name: "Google"},
				Version: "2.0.0",
			},
			Scanner: gitlab.AnalyzerDetails{
				ID:      "osv-scanner",
				Name:    "osv-scanner",
				URL:     "https://github.com/google/osv-scanner",
				Vendor:  gitlab.Vendor{Name: "Google"},
				Version: "2.0.0",
			},
			Type:      gitlab.CategoryDependencyScanning,
			Status:    gitlab.StatusSuccess,
			StartTime: "2025-01-01T12:00:00",
			EndTime:   "2025-01-01T12:00:01",
		},
	}

	validateGitLabReport(t, schemaLoader, report)
}

func TestReport_AllSeverityLevels(t *testing.T) {
	schemaLoader := loadGitLabSchema(t, "dependency-scanning-report-format.json")

	severities := []gitlab.SeverityLevel{
		gitlab.SeverityLevelCritical,
		gitlab.SeverityLevelHigh,
		gitlab.SeverityLevelMedium,
		gitlab.SeverityLevelLow,
		gitlab.SeverityLevelInfo,
		gitlab.SeverityLevelUnknown,
	}

	for _, severity := range severities {
		t.Run(severity.String(), func(t *testing.T) {
			report := gitlab.Report{
				Version: gitlab.CurrentVersion(),
				Vulnerabilities: []gitlab.Vulnerability{
					{
						Name:     "CVE-2023-0001",
						Severity: severity,
						Location: gitlab.Location{
							File: "/app/package.json",
							Dependency: &gitlab.Dependency{
								Package: gitlab.Package{Name: "test-pkg"},
								Version: "1.0.0",
							},
						},
						Identifiers: []gitlab.Identifier{
							{
								Type:  gitlab.IdentifierTypeCVE,
								Name:  "CVE-2023-0001",
								Value: "CVE-2023-0001",
							},
						},
					},
				},
				Scan: gitlab.Scan{
					Analyzer: gitlab.AnalyzerDetails{
						ID:      "osv-scanner",
						Name:    "osv-scanner",
						URL:     "https://github.com/google/osv-scanner",
						Vendor:  gitlab.Vendor{Name: "Google"},
						Version: "2.0.0",
					},
					Scanner: gitlab.AnalyzerDetails{
						ID:      "osv-scanner",
						Name:    "osv-scanner",
						URL:     "https://github.com/google/osv-scanner",
						Vendor:  gitlab.Vendor{Name: "Google"},
						Version: "2.0.0",
					},
					Type:      gitlab.CategoryDependencyScanning,
					Status:    gitlab.StatusSuccess,
					StartTime: "2025-01-01T12:00:00",
					EndTime:   "2025-01-01T12:00:01",
				},
			}

			validateGitLabReport(t, schemaLoader, report)
		})
	}
}

func TestReport_AllIdentifierTypes(t *testing.T) {
	schemaLoader := loadGitLabSchema(t, "dependency-scanning-report-format.json")

	identifiers := []struct {
		idType gitlab.IdentifierType
		name   string
		value  string
	}{
		{gitlab.IdentifierTypeCVE, "CVE-2023-1234", "CVE-2023-1234"},
		{gitlab.IdentifierTypeCWE, "CWE-79", "79"},
		{gitlab.IdentifierTypeGHSA, "GHSA-xxxx-yyyy-zzzz", "GHSA-xxxx-yyyy-zzzz"},
		{gitlab.IdentifierTypeGLAM, "GLAM-12345", "GLAM-12345"},
		{gitlab.IdentifierTypeMAL, "MAL-2023-1234", "MAL-2023-1234"},
		{gitlab.IdentifierTypeRHSA, "RHSA-2023:1234", "RHSA-2023:1234"},
		{gitlab.IdentifierTypeUSN, "USN-1234-1", "USN-1234-1"},
		{gitlab.IdentifierTypeELSA, "ELSA-2023-1234", "ELSA-2023-1234"},
		{gitlab.IdentifierTypeH1, "HACKERONE-12345", "12345"},
	}

	for _, id := range identifiers {
		t.Run(string(id.idType), func(t *testing.T) {
			report := gitlab.Report{
				Version: gitlab.CurrentVersion(),
				Vulnerabilities: []gitlab.Vulnerability{
					{
						Name:     id.name,
						Severity: gitlab.SeverityLevelMedium,
						Location: gitlab.Location{
							File: "/app/package.json",
							Dependency: &gitlab.Dependency{
								Package: gitlab.Package{Name: "test-pkg"},
								Version: "1.0.0",
							},
						},
						Identifiers: []gitlab.Identifier{
							{
								Type:  id.idType,
								Name:  id.name,
								Value: id.value,
							},
						},
					},
				},
				Scan: gitlab.Scan{
					Analyzer: gitlab.AnalyzerDetails{
						ID:      "osv-scanner",
						Name:    "osv-scanner",
						URL:     "https://github.com/google/osv-scanner",
						Vendor:  gitlab.Vendor{Name: "Google"},
						Version: "2.0.0",
					},
					Scanner: gitlab.AnalyzerDetails{
						ID:      "osv-scanner",
						Name:    "osv-scanner",
						URL:     "https://github.com/google/osv-scanner",
						Vendor:  gitlab.Vendor{Name: "Google"},
						Version: "2.0.0",
					},
					Type:      gitlab.CategoryDependencyScanning,
					Status:    gitlab.StatusSuccess,
					StartTime: "2025-01-01T12:00:00",
					EndTime:   "2025-01-01T12:00:01",
				},
			}

			validateGitLabReport(t, schemaLoader, report)
		})
	}
}

func TestReport_WithRemediations(t *testing.T) {
	schemaLoader := loadGitLabSchema(t, "dependency-scanning-report-format.json")

	vuln := gitlab.Vulnerability{
		Name:     "CVE-2023-1234",
		Severity: gitlab.SeverityLevelHigh,
		Location: gitlab.Location{
			File: "/app/package.json",
			Dependency: &gitlab.Dependency{
				Package: gitlab.Package{Name: "lodash"},
				Version: "4.17.20",
			},
		},
		Identifiers: []gitlab.Identifier{
			{
				Type:  gitlab.IdentifierTypeCVE,
				Name:  "CVE-2023-1234",
				Value: "CVE-2023-1234",
			},
		},
	}

	report := gitlab.Report{
		Version:         gitlab.CurrentVersion(),
		Vulnerabilities: []gitlab.Vulnerability{vuln},
		Remediations: []gitlab.Remediation{
			{
				Fixes:   []gitlab.Ref{gitlab.NewRef(vuln)},
				Summary: "Upgrade lodash to 4.17.21",
				Diff:    "ZGlmZiAtLWdpdCBhL3BhY2thZ2UuanNvbiBiL3BhY2thZ2UuanNvbg==", // base64 encoded diff
			},
		},
		Scan: gitlab.Scan{
			Analyzer: gitlab.AnalyzerDetails{
				ID:      "osv-scanner",
				Name:    "osv-scanner",
				URL:     "https://github.com/google/osv-scanner",
				Vendor:  gitlab.Vendor{Name: "Google"},
				Version: "2.0.0",
			},
			Scanner: gitlab.AnalyzerDetails{
				ID:      "osv-scanner",
				Name:    "osv-scanner",
				URL:     "https://github.com/google/osv-scanner",
				Vendor:  gitlab.Vendor{Name: "Google"},
				Version: "2.0.0",
			},
			Type:      gitlab.CategoryDependencyScanning,
			Status:    gitlab.StatusSuccess,
			StartTime: "2025-01-01T12:00:00",
			EndTime:   "2025-01-01T12:00:01",
		},
	}

	validateGitLabReport(t, schemaLoader, report)
}
