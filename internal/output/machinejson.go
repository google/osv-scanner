package output

import (
	"encoding/json"
	"fmt"
	"io"

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
	Vulnerabilities []slimVulnerability

	models.PackageVulns //nolint:embeddedstructfieldcheck // needs to be here to preserve field order
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
			aliased.Results[i].Packages[j].Vulnerabilities = make([]slimVulnerability, len(pkg.Vulnerabilities))

			for k, vuln := range pkg.Vulnerabilities {
				aliased.Results[i].Packages[j].Vulnerabilities[k] = slimVulnerability{vuln}
			}
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
