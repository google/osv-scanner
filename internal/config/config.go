// Package config manages the configuration for osv-scanner.
package config

import (
	"slices"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

var OSVScannerConfigName = "osv-scanner.toml"

type Config struct {
	IgnoredVulns      []*IgnoreEntry          `toml:"IgnoredVulns"`
	PackageOverrides  []*PackageOverrideEntry `toml:"PackageOverrides"`
	GoVersionOverride string                  `toml:"GoVersionOverride"`
	ScanGoModVersion  bool                    `toml:"ScanGoModVersion"`
	// The path to config file that this config was loaded from,
	// set by the scanner after having successfully parsed the file
	LoadPath string `toml:"-"`
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

func (c *Config) UnusedPackageOverrides() []*PackageOverrideEntry {
	unused := make([]*PackageOverrideEntry, 0, len(c.PackageOverrides))

	for _, entry := range c.PackageOverrides {
		if !entry.Used {
			unused = append(unused, entry)
		}
	}

	return unused
}

// FindVulnIgnore returns the first ignore entry relating to the given vulnerability id
func (c *Config) FindVulnIgnore(vulnID string) *IgnoreEntry {
	index := slices.IndexFunc(c.IgnoredVulns, func(e *IgnoreEntry) bool { return e.ID == vulnID })
	if index == -1 {
		return nil
	}
	ignoredLine := c.IgnoredVulns[index]

	effectiveUntil := ignoredLine.EffectiveUntil

	if effectiveUntil.IsZero() {
		effectiveUntil = ignoredLine.IgnoreUntil
	}

	if isInEffect(effectiveUntil) {
		return ignoredLine
	}

	return nil
}

func (c *Config) findFirstRelevantPackageOverride(pkg *extractor.Package, condition func(*PackageOverrideEntry) bool) *PackageOverrideEntry {
	index := slices.IndexFunc(c.PackageOverrides, func(e *PackageOverrideEntry) bool {
		return e.matches(pkg) && condition(e)
	})
	if index == -1 {
		return nil
	}
	ignoredLine := c.PackageOverrides[index]

	if isInEffect(ignoredLine.EffectiveUntil) {
		return ignoredLine
	}

	return nil
}

// FindIgnorePackageOverride returns the first override entry relating to ignoring the given package entirely
func (c *Config) FindIgnorePackageOverride(pkg *extractor.Package) *PackageOverrideEntry {
	return c.findFirstRelevantPackageOverride(pkg, func(e *PackageOverrideEntry) bool {
		return e.Ignore
	})
}

// FindPackageVulnerabilitiesOverride returns the first override entry relating to vulnerabilities for the given package
func (c *Config) FindPackageVulnerabilitiesOverride(pkg *extractor.Package) *PackageOverrideEntry {
	return c.findFirstRelevantPackageOverride(pkg, func(e *PackageOverrideEntry) bool {
		return e.Vulnerability.Ignore
	})
}

// FindPackageLicenseOverride returns the first override entry relating to licenses for the given package
func (c *Config) FindPackageLicenseOverride(pkg *extractor.Package) *PackageOverrideEntry {
	return c.findFirstRelevantPackageOverride(pkg, func(e *PackageOverrideEntry) bool {
		return e.License.Ignore || len(e.License.Override) > 0
	})
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

func (c *Config) warnAboutIgnoreUntil() {
	for _, vuln := range c.IgnoredVulns {
		if !vuln.IgnoreUntil.IsZero() {
			cmdlogger.Warnf("warning: %s has at least one ignore entry using 'ignoreUntil' which has been deprecated in favor of 'effectiveUntil'", c.LoadPath)

			break
		}
	}
}

// isInEffect reports whether the given effectiveUntil time is zero or comes
// after the current time, indicating the entry it came from should be
// considered in effect
func isInEffect(effectiveUntil time.Time) bool {
	return effectiveUntil.IsZero() || effectiveUntil.After(time.Now())
}
