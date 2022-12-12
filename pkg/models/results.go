package models

import "time"

// Combined vulnerabilities found for the scanned packages
type VulnerabilityResults struct {
	Results []PackageSource `json:"results"`
}

// Flatten the grouped/nested vulnerability results into one flat array.
func (vulns *VulnerabilityResults) Flatten() []VulnerabilityFlattened {
	results := []VulnerabilityFlattened{}
	for _, res := range vulns.Results {
		for _, pkg := range res.Packages {
			for _, v := range pkg.Vulnerabilities {
				results = append(results, VulnerabilityFlattened{
					Source:        res.Source,
					Package:       pkg.Package,
					Vulnerability: v,
				})
			}
		}
	}
	return results
}

// Flattened Vulnerability Information.
type VulnerabilityFlattened struct {
	Source        SourceInfo
	Package       PackageInfo
	Vulnerability Vulnerability
}

type Vulnerability struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	Modified      time.Time `json:"modified"`
	Published     time.Time `json:"published"`
	Aliases       []string  `json:"aliases"`
	Summary       string    `json:"summary"`
	Details       string    `json:"details"`
	Affected      []struct {
		Package struct {
			Ecosystem string `json:"ecosystem,omitempty"`
			Name      string `json:"name,omitempty"`
			Purl      string `json:"purl,omitempty"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced,omitempty"`
				Fixed        string `json:"fixed,omitempty"`
				LastAffected string `json:"last_affected,omitempty"`
				Limit        string `json:"limit,omitempty"`
			} `json:"events"`
			DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
		} `json:"ranges"`
		Versions          []string               `json:"versions,omitempty"`
		DatabaseSpecific  map[string]interface{} `json:"database_specific,omitempty"`
		EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

type SourceInfo struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func (s SourceInfo) String() string {
	return s.Type + ":" + s.Path
}

// Vulnerabilities grouped by sources
type PackageSource struct {
	Source   SourceInfo     `json:"source"`
	Packages []PackageVulns `json:"packages"`
}

// Vulnerabilities grouped by package
type PackageVulns struct {
	Package         PackageInfo     `json:"package"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Groups          []GroupInfo     `json:"groups"`
}

type GroupInfo struct {
	IDs []string `json:"ids"`
}

// Specific package information
type PackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}
