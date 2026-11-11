package output

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/internal/osvdiet"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

type aliasVulnerabilityResults struct {
	Results []aliasPackageSource `json:"results"`

	models.VulnerabilityResults //nolint:embeddedstructfieldcheck // needs to be here to preserve field order
}

type aliasPackageSource struct {
	models.PackageSource

	Packages []aliasPackageVulns `json:"packages"`
}

type aliasPackageVulns struct {
	models.PackageVulns

	vulns []slimVulnerability
}

// MarshalJSON shadows the MarshalJSON promoted from the embedded
// models.PackageVulns, which would otherwise marshal the (slimmed)
// vulnerabilities directly without ever fattening them
func (a *aliasPackageVulns) MarshalJSON() ([]byte, error) {
	// avoid models.PackageVulns.MarshalJSON by using a method-less alias
	type plain models.PackageVulns

	return json.Marshal(&struct {
		*plain

		Vulnerabilities []slimVulnerability `json:"vulnerabilities,omitempty"`
	}{
		plain:           (*plain)(&a.PackageVulns),
		Vulnerabilities: a.vulns,
	})
}

type slimVulnerability struct {
	vuln *osvschema.Vulnerability
}

func (sv *slimVulnerability) MarshalJSON() ([]byte, error) {
	vuln, err := osvdiet.Fatten(sv.vuln)

	if err != nil {
		return nil, err
	}

	unstableJSON, err := protojson.Marshal(vuln)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vulnerability: %w", err)
	}
	var fullVuln any
	if err := json.Unmarshal(unstableJSON, &fullVuln); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(fullVuln, "", "  ")
	if err != nil {
		return nil, err
	}

	return b, nil
}

func aliasResults(vulnResult *models.VulnerabilityResults) aliasVulnerabilityResults {
	aliased := aliasVulnerabilityResults{VulnerabilityResults: *vulnResult}

	aliased.Results = make([]aliasPackageSource, len(vulnResult.Results))

	for i, ps := range vulnResult.Results {
		aliased.Results[i].PackageSource = ps
		aliased.Results[i].Packages = make([]aliasPackageVulns, len(ps.Packages))

		for j, pkg := range ps.Packages {
			aliased.Results[i].Packages[j].PackageVulns = pkg
			aliased.Results[i].Packages[j].vulns = make([]slimVulnerability, len(pkg.Vulnerabilities))

			for k, vuln := range pkg.Vulnerabilities {
				aliased.Results[i].Packages[j].vulns[k] = slimVulnerability{vuln}
			}

			// match the ordering applied by models.PackageVulns.MarshalJSON
			slices.SortFunc(aliased.Results[i].Packages[j].vulns, func(a, b slimVulnerability) int {
				return identifiers.IDSortFunc(a.vuln.GetId(), b.vuln.GetId())
			})
		}
	}

	return aliased
}

// PrintJSONResults writes results to the provided writer in JSON format
func PrintJSONResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")

	return encoder.Encode(aliasResults(vulnResult))
}
