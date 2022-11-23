package models

// Combined vulnerabilities found for the scanned packages
type VulnerabilityResults struct {
	Results []SourceResults `json:"results"`
}

// Vulnerability represents a vulnerability entry from OSV.
type Vulnerability struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	// TODO(ochang): Add other fields.
}

type Source struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func (s Source) String() string {
	return s.Type + ":" + s.Path
}

// Vulnerabilities grouped by sources
type SourceResults struct {
	PackageSource Source    `json:"packageSource"`
	Packages      []Package `json:"packages"`
}

// Vulnerabilities grouped by package
type Package struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Ecosystem       string          `json:"ecosystem"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
