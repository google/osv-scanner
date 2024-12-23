package models

import (
	"slices"
	"strings"
)

// Combined vulnerabilities found for the scanned packages
type VulnerabilityResults struct {
	Results                    []PackageSource            `json:"results"`
	ExperimentalAnalysisConfig ExperimentalAnalysisConfig `json:"experimental_config"`
}

// ExperimentalAnalysisConfig is an experimental type intended to contain the
// types of analysis performed on packages found by the scanner.
type ExperimentalAnalysisConfig struct {
	Licenses ExperimentalLicenseConfig `json:"licenses"`
}

type ExperimentalLicenseConfig struct {
	Summary   bool      `json:"summary"`
	Allowlist []License `json:"allowlist"`
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
					DepGroups:     pkg.DepGroups,
					Vulnerability: v,
					GroupInfo:     getGroupInfoForVuln(pkg.Groups, v.ID),
				})
			}
			if len(pkg.LicenseViolations) > 0 {
				results = append(results, VulnerabilityFlattened{
					Source:            res.Source,
					Package:           pkg.Package,
					DepGroups:         pkg.DepGroups,
					Licenses:          pkg.Licenses,
					LicenseViolations: pkg.LicenseViolations,
				})
			}
		}
	}

	return results
}

func getGroupInfoForVuln(groups []GroupInfo, vulnID string) GroupInfo {
	// groupIdx should never be -1 since vulnerabilities should always be in one group
	groupIdx := slices.IndexFunc(groups, func(g GroupInfo) bool { return slices.Contains(g.IDs, vulnID) })
	return groups[groupIdx]
}

// Flattened Vulnerability Information.
// TODO: rename this to IssueFlattened or similar in the next major release as
// it now contains license violations.
type VulnerabilityFlattened struct {
	Source            SourceInfo
	Package           PackageInfo
	DepGroups         []string
	Vulnerability     Vulnerability
	GroupInfo         GroupInfo
	Licenses          []License
	LicenseViolations []License
}

type SourceInfo struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type Metadata struct {
	RepoURL   string   `json:"repo_url"`
	DepGroups []string `json:"-"`
}

func (s SourceInfo) String() string {
	return s.Type + ":" + s.Path
}

// Vulnerabilities grouped by sources
type PackageSource struct {
	Source   SourceInfo     `json:"source"`
	Packages []PackageVulns `json:"packages"`
}

// License is an SPDX license.
type License string

// Vulnerabilities grouped by package
// TODO: rename this to be Package as it now includes license information too.
type PackageVulns struct {
	Package           PackageInfo     `json:"package"`
	DepGroups         []string        `json:"dependency_groups,omitempty"`
	Vulnerabilities   []Vulnerability `json:"vulnerabilities,omitempty"`
	Groups            []GroupInfo     `json:"groups,omitempty"`
	Licenses          []License       `json:"licenses,omitempty"`
	LicenseViolations []License       `json:"license_violations,omitempty"`
}

type GroupInfo struct {
	// IDs expected to be sorted in alphanumeric order
	IDs []string `json:"ids"`
	// Aliases include all aliases and IDs
	Aliases []string `json:"aliases"`
	// Map of Vulnerability IDs to AnalysisInfo
	ExperimentalAnalysis map[string]AnalysisInfo `json:"experimentalAnalysis,omitempty"`
	MaxSeverity          string                  `json:"max_severity"`
}

// IsCalled returns true if any analysis performed determines that the vulnerability is being called
// Also returns true if no analysis is performed
func (groupInfo *GroupInfo) IsCalled() bool {
	if len(groupInfo.IDs) == 0 {
		// This PackageVulns may be a license violation, not a
		// vulnerability.
		return false
	}

	if len(groupInfo.ExperimentalAnalysis) == 0 {
		return true
	}

	for _, analysis := range groupInfo.ExperimentalAnalysis {
		if analysis.Called {
			return true
		}
	}

	return false
}

func (groupInfo *GroupInfo) IsGroupUnimportant() bool {
	if len(groupInfo.IDs) == 0 {
		return false
	}

	if len(groupInfo.ExperimentalAnalysis) == 0 {
		return false
	}

	for _, analysis := range groupInfo.ExperimentalAnalysis {
		if analysis.Unimportant {
			return true
		}
	}

	return false
}

func (groupInfo *GroupInfo) IndexString() string {
	// Assumes IDs is sorted
	return strings.Join(groupInfo.IDs, ",")
}

// FixedVersions returns a map of fixed versions for each package, or a map of empty slices if no fixed versions are available
func (v Vulnerability) FixedVersions() map[Package][]string {
	output := map[Package][]string{}
	for _, a := range v.Affected {
		packageKey := a.Package
		packageKey.Purl = ""
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					output[packageKey] = append(output[packageKey], e.Fixed)
					if strings.Contains(string(packageKey.Ecosystem), ":") {
						packageKey.Ecosystem = Ecosystem(strings.Split(string(packageKey.Ecosystem), ":")[0])
					}
					output[packageKey] = append(output[packageKey], e.Fixed)
				}
			}
		}
	}

	return output
}

type AnalysisInfo struct {
	Called      bool `json:"called"`
	Unimportant bool `json:"unimportant"`
}

// Specific package information
type PackageInfo struct {
	Name        string              `json:"name"`
	Version     string              `json:"version"`
	Ecosystem   string              `json:"ecosystem"`
	Commit      string              `json:"commit,omitempty"`
	ImageOrigin *ImageOriginDetails `json:"imageOrigin,omitempty"`
}
