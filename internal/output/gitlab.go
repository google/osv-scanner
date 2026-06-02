package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/osv-scanner/v2/internal/output/gitlab"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// GitlabTimeNow is used to get the current time for GitLab reports.
// It can be overridden in tests to produce deterministic output.
var GitlabTimeNow = time.Now

func PrintGitLabResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	scanType := determineScanType(vulnResult)
	vulnerabilities := buildVulnerabilities(vulnResult, scanType)
	report := buildReport(vulnerabilities, scanType)
	return encodeReport(report, outputWriter)
}

func determineScanType(vulnResult *models.VulnerabilityResults) gitlab.Category {
	if vulnResult.ImageMetadata != nil {
		return gitlab.CategoryContainerScanning
	}
	return gitlab.CategoryDependencyScanning
}

func buildVulnerabilities(vulnResult *models.VulnerabilityResults, scanType gitlab.Category) []gitlab.Vulnerability {
	vulnerabilities := make([]gitlab.Vulnerability, 0)
	for _, result := range vulnResult.Results {
		for _, packageItem := range result.Packages {
			for _, vulnerability := range packageItem.Vulnerabilities {
				gitlabVuln := buildVulnerability(vulnerability, packageItem, result, vulnResult, scanType)
				vulnerabilities = append(vulnerabilities, gitlabVuln)
			}
		}
	}
	return vulnerabilities
}

func buildVulnerability(vulnerability *osvschema.Vulnerability, packageItem models.PackageVulns, result models.PackageSource, vulnResult *models.VulnerabilityResults, scanType gitlab.Category) gitlab.Vulnerability {
	severityLevel := gitlab.SeverityLevelUnknown
	_, rating, err := severity.CalculateScoreBasedOnMostRecentCvssVersionAvailable(vulnerability.GetSeverity())
	// Keep the "Unknown" default when the rating can't be mapped to a defined level
	// (e.g. a "NONE" rating from a 0.0 CVSS score), so the severity is never silently
	// dropped from the report by the omitempty zero value.
	if mapped := gitlab.MapRatingToSeverityLevel(rating); err == nil && mapped != gitlab.SeverityLevelUndefined {
		severityLevel = mapped
	}

	return gitlab.Vulnerability{
		Name:        vulnerability.GetId(),
		Message:     vulnerability.GetSummary(),
		Description: vulnerability.GetDetails(),
		Severity:    severityLevel,
		Solution:    "No solution provided",
		Location:    buildLocation(packageItem, result, vulnResult, scanType),
		Identifiers: buildIdentifiers(vulnerability),
		CVSSRatings: buildCVSSRatings(vulnerability.GetSeverity()),
		Links:       buildLinks(vulnerability.GetReferences()),
	}
}

func buildLocation(packageItem models.PackageVulns, result models.PackageSource, vulnResult *models.VulnerabilityResults, scanType gitlab.Category) gitlab.Location {
	dependency := &gitlab.Dependency{
		Package: gitlab.Package{Name: packageItem.Package.Name},
		Version: packageItem.Package.Version,
	}

	if scanType == gitlab.CategoryContainerScanning {
		return gitlab.Location{
			Dependency:      dependency,
			OperatingSystem: vulnResult.ImageMetadata.OS,
			Image:           result.Source.Path,
		}
	}
	return gitlab.Location{
		File:       result.Source.Path,
		Dependency: dependency,
		Files:      buildFiles(result.Source),
	}
}

func buildFiles(source models.SourceInfo) []gitlab.File {
	// GitLab's FileType enum only distinguishes requirements/lockfile/graphfile, and
	// osv-scanner's SourceType does not carry that distinction (every project source is
	// SourceTypeProjectPackage="lockfile"), so all dependency sources are reported as lockfiles.
	return []gitlab.File{
		{
			Path: source.Path,
			Type: gitlab.FileTypeLockfile,
		},
	}
}

func buildIdentifiers(vulnerability *osvschema.Vulnerability) []gitlab.Identifier {
	identifiers := make([]gitlab.Identifier, 0)
	if id, ok := gitlab.ParseIdentifierID(vulnerability.GetId()); ok {
		identifiers = append(identifiers, id)
	}
	for _, alias := range vulnerability.GetAliases() {
		if id, ok := gitlab.ParseIdentifierID(alias); ok {
			identifiers = append(identifiers, id)
		}
	}
	// GitLab schema requires at least one identifier. If no known identifier types
	// were parsed, use the vulnerability ID with a
	// generic "osv" type.
	if len(identifiers) == 0 {
		identifiers = append(identifiers, gitlab.Identifier{
			Type:  "osv",
			Name:  vulnerability.GetId(),
			Value: vulnerability.GetId(),
		})
	}
	return identifiers
}

func buildCVSSRatings(severities []*osvschema.Severity) []gitlab.CVSSRating {
	ratings := make([]gitlab.CVSSRating, 0, len(severities))
	for _, sev := range severities {
		// Only CVSS severities carry a CVSS vector string. Other types (e.g. Ubuntu)
		// store a rating word in GetScore(), which is not a valid cvss_vectors value.
		if !isCVSSSeverity(sev.GetType()) {
			continue
		}
		ratings = append(ratings, gitlab.CVSSRating{
			Vendor: "unknown",
			Vector: sev.GetScore(),
		})
	}
	return ratings
}

func isCVSSSeverity(t osvschema.Severity_Type) bool {
	switch t {
	case osvschema.Severity_CVSS_V2, osvschema.Severity_CVSS_V3, osvschema.Severity_CVSS_V4:
		return true
	default:
		return false
	}
}

func buildLinks(references []*osvschema.Reference) []gitlab.Link {
	links := make([]gitlab.Link, 0, len(references))
	for _, ref := range references {
		links = append(links, gitlab.Link{URL: ref.GetUrl()})
	}
	return links
}

func buildReport(vulnerabilities []gitlab.Vulnerability, scanType gitlab.Category) gitlab.Report {
	return gitlab.Report{
		Version:         gitlab.CurrentVersion(),
		Vulnerabilities: vulnerabilities,
		Scan:            buildScanDetails(scanType),
	}
}

// gitlabTimeFormat is the ISO8601 UTC format required by GitLab schema (yyyy-mm-ddThh:mm:ss)
const gitlabTimeFormat = "2006-01-02T15:04:05"

func buildScanDetails(scanType gitlab.Category) gitlab.Scan {
	analyzerDetails := gitlab.AnalyzerDetails{
		ID:      "osv-scanner",
		Name:    "osv-scanner",
		URL:     "https://github.com/google/osv-scanner",
		Vendor:  gitlab.Vendor{Name: "Google"},
		Version: version.OSVVersion,
	}
	now := GitlabTimeNow().UTC().Format(gitlabTimeFormat)
	return gitlab.Scan{
		Analyzer:  analyzerDetails,
		Scanner:   analyzerDetails,
		Type:      scanType,
		Status:    gitlab.StatusSuccess,
		StartTime: now,
		EndTime:   now,
	}
}

func encodeReport(report gitlab.Report, outputWriter io.Writer) error {
	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
