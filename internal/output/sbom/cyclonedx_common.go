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
	components := make([]cyclonedx.Component, 0, len(uniquePackages))
	vulnerabilities := make(map[string]cyclonedx.Vulnerability)

	for packageURL, packageDetail := range uniquePackages {
		component := cyclonedx.Component{}

		component.Type = libraryComponentType
		component.BOMRef = packageURL
		component.PackageURL = packageURL
		component.Name = packageDetail.Package.Name
		component.Version = packageDetail.Package.Version

		addDeprecatedProperty(&component, packageDetail)
		fillLicenses(&component, packageDetail)
		addVulnerabilities(vulnerabilities, packageDetail)

		components = append(components, component)
	}

	slices.SortFunc(components, func(a, b cyclonedx.Component) int {
		return strings.Compare(a.PackageURL, b.PackageURL)
	})

	bomVulnerabilities := make([]cyclonedx.Vulnerability, 0, len(vulnerabilities))

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
		if _, exists := vulnerabilities[vulnerability.GetId()]; exists {
			continue
		}

		// It doesn't exist yet, lets add it
		vulnerabilities[vulnerability.GetId()] = cyclonedx.Vulnerability{
			ID:          vulnerability.GetId(),
			Updated:     formatDateIfExists(vulnerability.GetModified()),
			Published:   formatDateIfExists(vulnerability.GetPublished()),
			Rejected:    formatDateIfExists(vulnerability.GetWithdrawn()),
			References:  buildReferences(vulnerability),
			Description: vulnerability.GetSummary(),
			Detail:      vulnerability.GetDetails(),
			Affects:     buildAffectedPackages(vulnerability),
			Ratings:     buildRatings(vulnerability),
			Advisories:  buildAdvisories(vulnerability),
			Credits:     buildCredits(vulnerability),
		}
	}
}

func addDeprecatedProperty(component *cyclonedx.Component, packageDetail models.PackageVulns) {
	if !packageDetail.Package.Deprecated {
		return
	}

	component.Properties = &[]cyclonedx.Property{
		{
			Name:  "deprecated",
			Value: "true",
		},
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
	organizations := make([]cyclonedx.OrganizationalEntity, len(vulnerability.GetCredits()))

	for index, credit := range vulnerability.GetCredits() {
		organizations[index] = cyclonedx.OrganizationalEntity{
			Name: credit.GetName(),
			URL:  &vulnerability.GetCredits()[index].Contact,
		}
	}

	return &cyclonedx.Credits{
		Organizations: &organizations,
	}
}

func buildAffectedPackages(vulnerability *osvschema.Vulnerability) *[]cyclonedx.Affects {
	uniqueRefs := make(map[string]bool)
	affectedPackages := make([]cyclonedx.Affects, 0)

	for _, affected := range vulnerability.GetAffected() {
		if _, exists := uniqueRefs[affected.GetPackage().GetPurl()]; exists {
			continue
		}
		uniqueRefs[affected.GetPackage().GetPurl()] = true
		affectedPackages = append(affectedPackages, cyclonedx.Affects{
			Ref: affected.GetPackage().GetPurl(),
		})
	}

	return &affectedPackages
}

func buildRatings(vulnerability *osvschema.Vulnerability) *[]cyclonedx.VulnerabilityRating {
	ratings := make([]cyclonedx.VulnerabilityRating, len(vulnerability.GetSeverity()))
	for index, severity := range vulnerability.GetSeverity() {
		ratings[index] = cyclonedx.VulnerabilityRating{
			Method: SeverityMapper[severity.GetType()],
			Vector: severity.GetScore(),
		}
	}

	return &ratings
}

func buildReferences(vulnerability *osvschema.Vulnerability) *[]cyclonedx.VulnerabilityReference {
	references := make([]cyclonedx.VulnerabilityReference, len(vulnerability.GetAliases()))

	for index, alias := range vulnerability.GetAliases() {
		references[index] = cyclonedx.VulnerabilityReference{
			ID:     alias,
			Source: &cyclonedx.Source{},
		}
	}

	return &references
}

func buildAdvisories(vulnerability *osvschema.Vulnerability) *[]cyclonedx.Advisory {
	advisories := make([]cyclonedx.Advisory, 0)
	for _, reference := range vulnerability.GetReferences() {
		if reference.GetType() != osvschema.Reference_ADVISORY {
			continue
		}
		advisories = append(advisories, cyclonedx.Advisory{
			URL: reference.GetUrl(),
		})
	}

	return &advisories
}
