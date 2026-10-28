package config

import (
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/google/osv-scanner/v2/internal/imodels"
)

type PackageOverrideEntry struct {
	Name string `toml:"name"`
	// If the version is empty, the entry applies to all versions.
	Version        string        `toml:"version"`
	Ecosystem      string        `toml:"ecosystem"`
	Group          string        `toml:"group"`
	NameIsRegex    bool          `toml:"nameIsRegex"`
	Ignore         bool          `toml:"ignore"`
	Vulnerability  Vulnerability `toml:"vulnerability"`
	License        License       `toml:"license"`
	EffectiveUntil time.Time     `toml:"effectiveUntil"`
	Reason         string        `toml:"reason"`

	Used bool `toml:"-"`
}

func (e *PackageOverrideEntry) MarkAsUsed() {
	e.Used = true
}

func (e *PackageOverrideEntry) Describe() string {
	var parts []string

	if e.Ecosystem != "" {
		parts = append(parts, "Ecosystem: "+e.Ecosystem)
	}
	if e.Name != "" {
		parts = append(parts, "Name: "+e.Name)
	}
	if e.Version != "" {
		parts = append(parts, "Version: "+e.Version)
	}
	if e.Group != "" {
		parts = append(parts, "Group: "+e.Group)
	}
	if e.Reason != "" {
		parts = append(parts, "Reason: "+e.Reason)
	}

	if len(parts) == 0 {
		return "(blanket ignore)"
	}

	return strings.Join(parts, ", ")
}

func (e *PackageOverrideEntry) matches(pkg *extractor.Package) bool {
	parsedPkg := imodels.ParsePackage(pkg)
	if e.Name != "" {
		if e.NameIsRegex {
			re, err := cachedregexp.Compile("^(?:" + e.Name + ")$")
			if err != nil {
				// This should not happen as regex is validated at config load time
				return false
			}
			if !re.MatchString(parsedPkg.Name) {
				return false
			}
		} else if e.Name != parsedPkg.Name {
			return false
		}
	}
	if e.Version != "" && e.Version != parsedPkg.Version {
		return false
	}
	// If there is an ecosystem filter, the filter must not match both the:
	//  - Full ecosystem + suffix
	//  - The base ecosystem
	if e.Ecosystem != "" && (e.Ecosystem != parsedPkg.Ecosystem.String() && e.Ecosystem != string(parsedPkg.Ecosystem.Ecosystem)) {
		return false
	}
	if e.Group != "" && !slices.Contains(imodels.DepGroups(pkg), e.Group) {
		return false
	}

	return true
}

type Vulnerability struct {
	Ignore bool `toml:"ignore"`
}

type License struct {
	Override []string `toml:"override"`
	Ignore   bool     `toml:"ignore"`
}

// OmitUnexpiredLicenseOverrides removes any overrides that relate only to licenses
func OmitUnexpiredLicenseOverrides(overrides []*PackageOverrideEntry) []*PackageOverrideEntry {
	var collected []*PackageOverrideEntry

	for _, override := range overrides {
		hasLicenseOverride := override.License.Ignore || len(override.License.Override) > 0

		if isInEffect(override.EffectiveUntil) && hasLicenseOverride && !override.Ignore && !override.Vulnerability.Ignore {
			continue
		}

		collected = append(collected, override)
	}

	return collected
}
