package sbom

import (
	"slices"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
)

func buildCycloneDXBom(uniquePackages map[string]models.PackageVulns) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	components := make([]cyclonedx.Component, 0)
	bomVulnerabilities := make([]cyclonedx.Vulnerability, 0)
	vulnerabilities := make(map[string]cyclonedx.Vulnerability)

	for packageURL, packageDetail := range uniquePackages {
		component := cyclonedx.Component{}

		component.Type = libraryComponentType
		component.BOMRef = packageURL
		component.PackageURL = packageURL
		component.Name = packageDetail.Package.Name
		component.Version = packageDetail.Package.Version

		fillLicenses(&component, packageDetail)
		addVulnerabilities(vulnerabilities, packageDetail)

		components = append(components, component)
	}

	slices.SortFunc(components, func(a, b cyclonedx.Component) int {
		return strings.Compare(a.PackageURL, b.PackageURL)
	})

	for _, vulnerability := range vulnerabilities {
		bomVulnerabilities = append(bomVulnerabilities, vulnerability)
	}

	slices.SortFunc(bomVulnerabilities, func(a, b cyclonedx.Vulnerability) int {
		return strings.Compare(a.ID, b.ID)
	})

	bom.Components = &components
	bom.Vulnerabilities = &bomVulnerabilities

	return bom
}

func fillLicenses(component *cyclonedx.Component, packageDetail models.PackageVulns) {
	licenses := make(cyclonedx.Licenses, len(packageDetail.Licenses))

	for index, license := range packageDetail.Licenses {
		licenses[index] = cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				ID: string(license),
			},
		}
	}
	component.Licenses = &licenses
}

func addVulnerabilities(vulnerabilities map[string]cyclonedx.Vulnerability, packageDetail models.PackageVulns) {
	for _, vulnerability := range packageDetail.Vulnerabilities {
		if _, exists := vulnerabilities[vulnerability.ID]; exists {
			continue
		}

		// It doesn't exists yet, lets add it
		vulnerabilities[vulnerability.ID] = cyclonedx.Vulnerability{
			ID:          vulnerability.ID,
			Updated:     formatDateIfExists(vulnerability.Modified),
			Published:   formatDateIfExists(vulnerability.Published),
			Rejected:    formatDateIfExists(vulnerability.Withdrawn),
			References:  buildReferences(vulnerability),
			Description: vulnerability.Summary,
			Detail:      vulnerability.Details,
			Affects:     buildAffectedPackages(vulnerability),
			Ratings:     buildRatings(vulnerability),
			Advisories:  buildAdvisories(vulnerability),
			Credits:     buildCredits(vulnerability),
		}
	}
}

func formatDateIfExists(date time.Time) string {
	if date.IsZero() {
		return ""
	}

	return date.Format(time.RFC3339)
}

func buildCredits(vulnerability models.Vulnerability) *cyclonedx.Credits {
	organizations := make([]cyclonedx.OrganizationalEntity, len(vulnerability.Credits))

	for index, credit := range vulnerability.Credits {
		organizations[index] = cyclonedx.OrganizationalEntity{
			Name: credit.Name,
			URL:  &vulnerability.Credits[index].Contact,
		}
	}

	return &cyclonedx.Credits{
		Organizations: &organizations,
	}
}

func buildAffectedPackages(vulnerability models.Vulnerability) *[]cyclonedx.Affects {
	affectedPackages := make([]cyclonedx.Affects, len(vulnerability.Affected))

	for index, affected := range vulnerability.Affected {
		affectedPackages[index] = cyclonedx.Affects{
			Ref: affected.Package.Purl,
		}
	}

	return &affectedPackages
}

func buildRatings(vulnerability models.Vulnerability) *[]cyclonedx.VulnerabilityRating {
	ratings := make([]cyclonedx.VulnerabilityRating, len(vulnerability.Severity))
	for index, severity := range vulnerability.Severity {
		ratings[index] = cyclonedx.VulnerabilityRating{
			Method: SeverityMapper[severity.Type],
			Vector: severity.Score,
		}
	}

	return &ratings
}

func buildReferences(vulnerability models.Vulnerability) *[]cyclonedx.VulnerabilityReference {
	references := make([]cyclonedx.VulnerabilityReference, len(vulnerability.Aliases))

	for index, alias := range vulnerability.Aliases {
		references[index] = cyclonedx.VulnerabilityReference{
			ID:     alias,
			Source: &cyclonedx.Source{},
		}
	}

	return &references
}

func buildAdvisories(vulnerability models.Vulnerability) *[]cyclonedx.Advisory {
	advisories := make([]cyclonedx.Advisory, 0)
	for _, reference := range vulnerability.References {
		if reference.Type != models.ReferenceAdvisory {
			continue
		}
		advisories = append(advisories, cyclonedx.Advisory{
			URL: reference.URL,
		})
	}

	return &advisories
}
