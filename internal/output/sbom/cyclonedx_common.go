package sbom

import (
	"slices"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	for i := range packageDetail.Vulnerabilities {
		vulnerability := packageDetail.Vulnerabilities[i]
		if _, exists := vulnerabilities[vulnerability.Id]; exists {
			continue
		}

		// It doesn't exist yet, lets add it
		vulnerabilities[vulnerability.Id] = cyclonedx.Vulnerability{
			ID:          vulnerability.Id,
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

func formatDateIfExists(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	t := ts.AsTime()
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func buildCredits(vulnerability *osvschema.Vulnerability) *cyclonedx.Credits {
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

func buildAffectedPackages(vulnerability *osvschema.Vulnerability) *[]cyclonedx.Affects {
	uniqueRefs := make(map[string]bool)
	affectedPackages := make([]cyclonedx.Affects, 0)

	for _, affected := range vulnerability.Affected {
		if _, exists := uniqueRefs[affected.Package.Purl]; exists {
			continue
		}
		uniqueRefs[affected.Package.Purl] = true
		affectedPackages = append(affectedPackages, cyclonedx.Affects{
			Ref: affected.Package.Purl,
		})
	}

	return &affectedPackages
}

func buildRatings(vulnerability *osvschema.Vulnerability) *[]cyclonedx.VulnerabilityRating {
	ratings := make([]cyclonedx.VulnerabilityRating, len(vulnerability.Severity))
	for index, severity := range vulnerability.Severity {
		ratings[index] = cyclonedx.VulnerabilityRating{
			Method: SeverityMapper[severity.Type],
			Vector: severity.Score,
		}
	}

	return &ratings
}

func buildReferences(vulnerability *osvschema.Vulnerability) *[]cyclonedx.VulnerabilityReference {
	references := make([]cyclonedx.VulnerabilityReference, len(vulnerability.Aliases))

	for index, alias := range vulnerability.Aliases {
		references[index] = cyclonedx.VulnerabilityReference{
			ID:     alias,
			Source: &cyclonedx.Source{},
		}
	}

	return &references
}

func buildAdvisories(vulnerability *osvschema.Vulnerability) *[]cyclonedx.Advisory {
	advisories := make([]cyclonedx.Advisory, 0)
	for _, reference := range vulnerability.References {
		if reference.Type != osvschema.Reference_ADVISORY {
			continue
		}
		advisories = append(advisories, cyclonedx.Advisory{
			URL: reference.Url,
		})
	}

	return &advisories
}
