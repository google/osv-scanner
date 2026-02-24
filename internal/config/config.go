// Package config manages the configuration for osv-scanner.
package config

import (
	"os"
	"slices"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var OSVScannerConfigName = "osv-scanner.toml"

type Config struct {
	IgnoredVulns      []*IgnoreEntry         `toml:"IgnoredVulns"`
	PackageOverrides  []PackageOverrideEntry `toml:"PackageOverrides"`
	GoVersionOverride string                 `toml:"GoVersionOverride,omitempty"`
	// The path to config file that this config was loaded from,
	// set by the scanner after having successfully parsed the file
	LoadPath string `toml:"-"`
}

type IgnoreEntry struct {
	ID          string    `toml:"id"`
	IgnoreUntil time.Time `toml:"ignoreUntil,omitempty"`
	Reason      string    `toml:"reason,omitempty"`

	Used bool `toml:"-"`
}

func (ie *IgnoreEntry) MarkAsUsed() {
	ie.Used = true
}

type PackageOverrideEntry struct {
	Name string `toml:"name"`
	// If the version is empty, the entry applies to all versions.
	Version        string        `toml:"version"`
	Ecosystem      string        `toml:"ecosystem"`
	Group          string        `toml:"group"`
	Ignore         bool          `toml:"ignore"`
	Vulnerability  Vulnerability `toml:"vulnerability"`
	License        License       `toml:"license"`
	EffectiveUntil time.Time     `toml:"effectiveUntil"`
	Reason         string        `toml:"reason"`
}

func (e PackageOverrideEntry) matches(pkg imodels.PackageInfo) bool {
	if e.Name != "" && e.Name != pkg.Name() {
		return false
	}
	if e.Version != "" && e.Version != pkg.Version() {
		return false
	}
	// If there is an ecosystem filter, the filter must not match both the:
	//  - Full ecosystem + suffix
	//  - The base ecosystem
	if e.Ecosystem != "" && (e.Ecosystem != pkg.Ecosystem().String() && e.Ecosystem != string(pkg.Ecosystem().Ecosystem)) {
		return false
	}
	if e.Group != "" && !slices.Contains(pkg.DepGroups(), e.Group) {
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

func (c *Config) UpdateFile(vulns []*osvschema.Vulnerability) error {
	existingIgnores := make(map[string]*IgnoreEntry, len(c.IgnoredVulns))
	for _, ignoredVuln := range c.IgnoredVulns {
		existingIgnores[ignoredVuln.ID] = ignoredVuln
	}

	// use a fresh slice to ensure vulns that are no longer present are removed
	c.IgnoredVulns = make([]*IgnoreEntry, 0, len(vulns))

	seen := make(map[string]struct{}, len(vulns))

	for _, vuln := range vulns {
		if _, ok := seen[vuln.GetId()]; ok {
			continue
		}

		// if the vuln was already ignored, we want to persist its other fields
		ignore, ok := existingIgnores[vuln.GetId()]

		if !ok {
			ignore = &IgnoreEntry{ID: vuln.GetId()}
		}

		c.IgnoredVulns = append(c.IgnoredVulns, ignore)
		seen[vuln.GetId()] = struct{}{}
	}

	slices.SortFunc(c.IgnoredVulns, func(a, b *IgnoreEntry) int {
		return identifiers.IDSortFunc(a.ID, b.ID)
	})

	return c.Save()
}

// Save writes the configuration file to disk, overriding the existing content
func (c *Config) Save() error {
	f, err := os.OpenFile(c.LoadPath, os.O_TRUNC|os.O_WRONLY, os.ModePerm)

	if err != nil {
		return err
	}

	encoder := toml.NewEncoder(f)
	encoder.Indent = ""

	return encoder.Encode(c)
}

func (c *Config) UnusedIgnoredVulns() []*IgnoreEntry {
	unused := make([]*IgnoreEntry, 0, len(c.IgnoredVulns))

	for _, entry := range c.IgnoredVulns {
		if !entry.Used {
			unused = append(unused, entry)
		}
	}

	return unused
}

func (c *Config) RemoveUnusedIgnores() {
	// todo: see if this is a more optimized way to do this?
	ignoredVulns := make([]*IgnoreEntry, 0, len(c.IgnoredVulns))

	for _, iv := range c.IgnoredVulns {
		if iv.Used {
			ignoredVulns = append(ignoredVulns, iv)
		}
	}

	c.IgnoredVulns = ignoredVulns
}

func (c *Config) ShouldIgnore(vulnID string) (bool, *IgnoreEntry) {
	index := slices.IndexFunc(c.IgnoredVulns, func(e *IgnoreEntry) bool { return e.ID == vulnID })
	if index == -1 {
		return false, &IgnoreEntry{}
	}
	ignoredLine := c.IgnoredVulns[index]

	return shouldIgnoreTimestamp(ignoredLine.IgnoreUntil), ignoredLine
}

func (c *Config) filterPackageVersionEntries(pkg imodels.PackageInfo, condition func(PackageOverrideEntry) bool) (bool, PackageOverrideEntry) {
	index := slices.IndexFunc(c.PackageOverrides, func(e PackageOverrideEntry) bool {
		return e.matches(pkg) && condition(e)
	})
	if index == -1 {
		return false, PackageOverrideEntry{}
	}
	ignoredLine := c.PackageOverrides[index]

	return shouldIgnoreTimestamp(ignoredLine.EffectiveUntil), ignoredLine
}

// ShouldIgnorePackage determines if the given package should be ignored based on override entries in the config
func (c *Config) ShouldIgnorePackage(pkg imodels.PackageInfo) (bool, PackageOverrideEntry) {
	return c.filterPackageVersionEntries(pkg, func(e PackageOverrideEntry) bool {
		return e.Ignore
	})
}

// ShouldIgnorePackageVulnerabilities determines if the given package should have its vulnerabilities ignored based on override entries in the config
func (c *Config) ShouldIgnorePackageVulnerabilities(pkg imodels.PackageInfo) bool {
	overrides, _ := c.filterPackageVersionEntries(pkg, func(e PackageOverrideEntry) bool {
		return e.Vulnerability.Ignore
	})

	return overrides
}

// ShouldOverridePackageLicense determines if the given package should have its license ignored or changed based on override entries in the config
func (c *Config) ShouldOverridePackageLicense(pkg imodels.PackageInfo) (bool, PackageOverrideEntry) {
	return c.filterPackageVersionEntries(pkg, func(e PackageOverrideEntry) bool {
		return e.License.Ignore || len(e.License.Override) > 0
	})
}

func shouldIgnoreTimestamp(ignoreUntil time.Time) bool {
	if ignoreUntil.IsZero() {
		// If IgnoreUntil is not set, should ignore.
		return true
	}
	// Should ignore if IgnoreUntil is still after current time
	// Takes timezone offsets into account if it is specified. otherwise it's using local time
	return ignoreUntil.After(time.Now())
}

func (c *Config) warnAboutDuplicates() {
	seen := make(map[string]struct{})

	for _, vuln := range c.IgnoredVulns {
		if _, ok := seen[vuln.ID]; ok {
			cmdlogger.Warnf("warning: %s has multiple ignores for %s - only the first will be used!", c.LoadPath, vuln.ID)
		}
		seen[vuln.ID] = struct{}{}
	}
}
