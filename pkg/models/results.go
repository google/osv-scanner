package models

import "github.com/google/osv-scanner/internal/osv"

// Combined vulnerabilities found for the scanned packages
type VulnerabilityResults struct {
	Results []SourceResults `json:"results"`
}

// Vulnerabilities grouped by sources
type SourceResults struct {
	PackageSource osv.Source `json:"packageSource"`
	Packages      []Package  `json:"packages"`
}

// Vulnerabilities grouped by package
type Package struct {
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	Ecosystem       string              `json:"ecosystem"`
	Vulnerabilities []osv.Vulnerability `json:"vulnerabilities"`
}
