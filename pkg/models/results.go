package models

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

// VulnerabilityResults is the top-level struct for the results of a scan
type VulnerabilityResults struct {
	Results                     []PackageSource             `json:"results"`
	ExperimentalAnalysisConfig  ExperimentalAnalysisConfig  `json:"experimental_config"`
	ExperimentalGenericFindings []*inventory.GenericFinding `json:"experimental_generic_findings,omitempty"`
	ImageMetadata               *ImageMetadata              `json:"image_metadata,omitempty"`
	LicenseSummary              []LicenseCount              `json:"license_summary,omitempty"`
}

type LicenseCount struct {
	Name  License `json:"name"`
	Count int     `json:"count"`
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
					GroupInfo:     getGroupInfoForVuln(pkg.Groups, v.GetId()),
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

// VulnerabilityFlattened is a flattened version of the VulnerabilityResults
// TODO: rename this to IssueFlattened or similar in the next major release as
// it now contains license violations.
type VulnerabilityFlattened struct {
	Source            SourceInfo
	Package           PackageInfo
	DepGroups         []string
	Vulnerability     *osvschema.Vulnerability
	GroupInfo         GroupInfo
	Licenses          []License
	LicenseViolations []License
}

// MarshalJSON implements the json.Marshaler interface.
// It is required because the Vulnerability field is a proto message,
// which requires protojson to marshal, while the rest of the struct uses
// the standard encoding/json library.
func (v *VulnerabilityFlattened) MarshalJSON() ([]byte, error) {
	// Use alias to avoid recursion.
	type alias VulnerabilityFlattened

	// Pre-process the custom field.
	var rawVulnerability json.RawMessage
	if v.Vulnerability != nil {
		marshaler := protojson.MarshalOptions{Indent: "  "}
		b, err := marshaler.Marshal(v.Vulnerability)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Vulnerability: %w", err)
		}
		rawVulnerability = b
	}

	// Marshal a temporary struct that combines the standard
	// fields (from the alias) with the custom-handled field.
	return json.Marshal(&struct {
		*alias

		Vulnerability json.RawMessage `json:"Vulnerability"`
	}{
		alias:         (*alias)(v),
		Vulnerability: rawVulnerability,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It is required because the Vulnerability field is a proto message,
// which requires protojson to unmarshal, while the rest of the struct uses
// the standard encoding/json library.
func (v *VulnerabilityFlattened) UnmarshalJSON(data []byte) error {
	// Unmarshal into a temporary struct with Vulnerability as json.RawMessage.
	// Use an alias to avoid an infinite recursion loop.
	type alias VulnerabilityFlattened
	tmp := &struct {
		*alias

		Vulnerability json.RawMessage `json:"Vulnerability"`
	}{
		alias: (*alias)(v),
	}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// If there is a vulnerability, unmarshal it using protojson.
	if len(tmp.Vulnerability) > 0 && string(tmp.Vulnerability) != "null" {
		v.Vulnerability = &osvschema.Vulnerability{}
		if err := protojson.Unmarshal(tmp.Vulnerability, v.Vulnerability); err != nil {
			return err
		}
	}

	return nil
}

// SourceType categorizes packages based on the extractor that extracted
// the "source", for use in the output.
type SourceType string

const (
	SourceTypeUnknown        SourceType = "unknown"
	SourceTypeOSPackage      SourceType = "os"
	SourceTypeProjectPackage SourceType = "lockfile"
	SourceTypeArtifact       SourceType = "artifact"
	SourceTypeSBOM           SourceType = "sbom"
	SourceTypeGit            SourceType = "git"
)

type SourceInfo struct {
	Path string     `json:"path"`
	Type SourceType `json:"type"`
}

type Metadata struct {
	RepoURL   string   `json:"repo_url"`
	DepGroups []string `json:"-"`
}

func (s SourceInfo) String() string {
	return string(s.Type) + ":" + s.Path
}

// PackageSource represents Vulnerabilities associated with a Source
type PackageSource struct {
	Source SourceInfo `json:"source"`
	// Place Annotations in PackageSource instead of SourceInfo as we need SourceInfo to be mappable
	ExperimentalAnnotations []extractor.Annotation `json:"experimental_annotations,omitempty"`
	Packages                []PackageVulns         `json:"packages"`
}

// License is an SPDX license.
type License string

// PackageVulns grouped by package
// TODO: rename this to be Package as it now includes license information too.
type PackageVulns struct {
	Package           PackageInfo                `json:"package"`
	DepGroups         []string                   `json:"dependency_groups,omitempty"`
	Vulnerabilities   []*osvschema.Vulnerability `json:"vulnerabilities,omitempty"`
	Groups            []GroupInfo                `json:"groups,omitempty"`
	Licenses          []License                  `json:"licenses,omitempty"`
	LicenseViolations []License                  `json:"license_violations,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface.
// It is required because the Vulnerabilities field is a slice of proto messages,
// which requires protojson to marshal, while the rest of the struct uses
// the standard encoding/json library.
func (p *PackageVulns) MarshalJSON() ([]byte, error) {
	// Use alias to avoid recursion.
	type alias PackageVulns

	// Pre-process the custom field.
	var rawVulnerabilities []json.RawMessage
	if len(p.Vulnerabilities) > 0 {
		rawVulnerabilities = make([]json.RawMessage, 0, len(p.Vulnerabilities))
		for _, vuln := range p.Vulnerabilities {
			marshaler := protojson.MarshalOptions{Indent: "  "}
			b, err := marshaler.Marshal(vuln)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal vulnerability: %w", err)
			}
			rawVulnerabilities = append(rawVulnerabilities, b)
		}
	}

	// Marshal a temporary struct that combines the standard
	// fields (from the alias) with the custom-handled field.
	return json.Marshal(&struct {
		*alias

		Vulnerabilities []json.RawMessage `json:"vulnerabilities,omitempty"`
	}{
		alias:           (*alias)(p),
		Vulnerabilities: rawVulnerabilities,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It is required because the Vulnerabilities field is a slice of proto messages,
// which requires protojson to unmarshal, while the rest of the struct uses
// the standard encoding/json library.
func (p *PackageVulns) UnmarshalJSON(data []byte) error {
	// Use alias to avoid recursion.
	type alias PackageVulns

	// Use temporary struct to combine standard fields (via alias)
	// and the manually processed field (via shadowing).
	tmp := &struct {
		*alias

		Vulnerabilities []json.RawMessage `json:"vulnerabilities,omitempty"`
	}{
		alias: (*alias)(p),
	}

	// Unmarshal into the temporary struct.
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// Manually process the custom field from RawMessage format.
	if len(tmp.Vulnerabilities) > 0 {
		p.Vulnerabilities = make([]*osvschema.Vulnerability, 0, len(tmp.Vulnerabilities))
		for i, rawVuln := range tmp.Vulnerabilities {
			vuln := &osvschema.Vulnerability{}
			if err := protojson.Unmarshal(rawVuln, vuln); err != nil {
				return fmt.Errorf("failed to protojson unmarshal vulnerability at index %d: %w", i, err)
			}
			p.Vulnerabilities = append(p.Vulnerabilities, vuln)
		}
	}

	return nil
}

type GroupInfo struct {
	// IDs expected to be sorted in alphanumeric order
	IDs []string `json:"ids"`
	// Aliases include all aliases and IDs
	Aliases []string `json:"aliases"`
	// Map of Vulnerability IDs to AnalysisInfo
	ExperimentalAnalysis map[string]AnalysisInfo `json:"experimental_analysis,omitempty"`
	MaxSeverity          string                  `json:"max_severity"`
}

// IsCalled returns true if any analysis performed determines that the vulnerability is being called
// Also returns true if no analysis is performed
func (groupInfo *GroupInfo) IsCalled() bool {
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

type AnalysisInfo struct {
	Called      bool `json:"called"`
	Unimportant bool `json:"unimportant"`
}

type PackageInfo struct {
	Name          string              `json:"name"`
	OSPackageName string              `json:"os_package_name,omitempty"`
	Version       string              `json:"version"`
	Ecosystem     string              `json:"ecosystem"`
	Commit        string              `json:"commit,omitempty"`
	ImageOrigin   *ImageOriginDetails `json:"image_origin_details,omitempty"`
	Inventory     *extractor.Package  `json:"-"`
}
