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

// plainPackageVulns is a method-less copy of models.PackageVulns, so that
// embedding it doesn't promote models.PackageVulns.MarshalJSON, which would
// otherwise marshal the (slimmed) vulnerabilities without ever fattening them
type plainPackageVulns models.PackageVulns

type aliasPackageVulns struct {
	plainPackageVulns

	// shadows plainPackageVulns.Vulnerabilities, as shallower fields
	// take precedence when marshaling
	Vulnerabilities []slimVulnerability `json:"vulnerabilities,omitempty"`
}

type slimVulnerability struct {
	client *osvdiet.Client
	vuln   *osvschema.Vulnerability
}

func (sv *slimVulnerability) MarshalJSON() ([]byte, error) {
	vuln, err := sv.client.Fatten(sv.vuln)

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

	return json.Marshal(fullVuln)
}

func aliasResults(vulnResult *models.VulnerabilityResults, dietClient *osvdiet.Client) aliasVulnerabilityResults {
	aliased := aliasVulnerabilityResults{VulnerabilityResults: *vulnResult}

	aliased.Results = make([]aliasPackageSource, len(vulnResult.Results))

	for i, ps := range vulnResult.Results {
		aliased.Results[i].PackageSource = ps
		aliased.Results[i].Packages = make([]aliasPackageVulns, len(ps.Packages))

		for j, pkg := range ps.Packages {
			aliased.Results[i].Packages[j].plainPackageVulns = plainPackageVulns(pkg)
			aliased.Results[i].Packages[j].Vulnerabilities = make([]slimVulnerability, len(pkg.Vulnerabilities))

			for k, vuln := range pkg.Vulnerabilities {
				aliased.Results[i].Packages[j].Vulnerabilities[k] = slimVulnerability{dietClient, vuln}
			}

			// match the ordering applied by models.PackageVulns.MarshalJSON
			slices.SortFunc(aliased.Results[i].Packages[j].Vulnerabilities, func(a, b slimVulnerability) int {
				return identifiers.IDSortFunc(a.vuln.GetId(), b.vuln.GetId())
			})
		}
	}

	return aliased
}

// PrintJSONResults writes results to the provided writer in JSON format
func PrintJSONResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, dietClient *osvdiet.Client) error {
	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")

	// if the diet client was used, alias the results
	// so they can be fattened as part of marshalling
	if dietClient != nil {
		return encoder.Encode(aliasResults(vulnResult, dietClient))
	}

	return encoder.Encode(vulnResult)
}
