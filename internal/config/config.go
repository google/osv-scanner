// Package config manages the configuration for osv-scanner.
package config

import (
	"bytes"
	"os"
	"slices"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/pkg/models"
)

var OSVScannerConfigName = "osv-scanner.toml"

type Config struct {
	GoVersionOverride string                  `toml:"GoVersionOverride,omitempty"`
	ScanGoModVersion  bool                    `toml:"ScanGoModVersion,omitempty"`
	PackageOverrides  []*PackageOverrideEntry `toml:"PackageOverrides,omitempty"`
	IgnoredVulns      []*IgnoreEntry          `toml:"IgnoredVulns,omitempty"`
	// The path to config file that this config was loaded from,
	// set by the scanner after having successfully parsed the file
	LoadPath string `toml:"-"`
}

// IgnoreVulns updates Config.IgnoredVulns to hold only entries for the given
// vulnerability groups, which are expected to come from models.PackageVulns.Groups
func (c *Config) IgnoreVulns(groups []models.GroupInfo) {
	existingIgnores := make(map[string]*IgnoreEntry, len(c.IgnoredVulns))
	for _, ignoredVuln := range c.IgnoredVulns {
		// keep the first entry if an id is configured more than once
		if _, ok := existingIgnores[ignoredVuln.ID]; !ok {
			existingIgnores[ignoredVuln.ID] = ignoredVuln
		}
	}

	// use a fresh slice to ensure vulns that are no longer present are removed
	c.IgnoredVulns = make([]*IgnoreEntry, 0, len(groups))

	// the ids of the entries we're keeping
	kept := make(map[string]struct{}, len(groups))

	for _, group := range groups {
		if isGroupCoveredBy(group, kept) {
			continue
		}

		// if the vuln was already ignored (possibly under an alias), we want to
		// keep that entry as is; this checks aliases in the same order as the
		// filtering does, so we keep the entry whose reason gets reported
		var ignore *IgnoreEntry
		for _, id := range group.Aliases {
			if ignore = existingIgnores[id]; ignore != nil {
				break
			}
		}

		if ignore == nil {
			ignore = &IgnoreEntry{ID: group.IDs[0]}
		}

		c.IgnoredVulns = append(c.IgnoredVulns, ignore)
		kept[ignore.ID] = struct{}{}
	}

	slices.SortFunc(c.IgnoredVulns, func(a, b *IgnoreEntry) int {
		return identifiers.IDSortFunc(a.ID, b.ID)
	})
}

// isGroupCoveredBy reports if the given group would be ignored by an entry
// with one of the given ids, as done when filtering results
func isGroupCoveredBy(group models.GroupInfo, ids map[string]struct{}) bool {
	return slices.ContainsFunc(group.Aliases, func(id string) bool {
		_, ok := ids[id]

		return ok
	})
}

// Save writes the configuration file to disk, overriding the existing content
func (c *Config) Save() error {
	var buf bytes.Buffer

	encoder := toml.NewEncoder(&buf)
	encoder.Indent = ""

	if err := encoder.Encode(c); err != nil {
		return err
	}

	// the permissions are only used if the file does not already exist
	return os.WriteFile(c.LoadPath, buf.Bytes(), 0o600)
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

func (c *Config) RemoveUnusedIgnores() []*IgnoreEntry {
	var removed []*IgnoreEntry
	filtered := c.IgnoredVulns[:0]

	for _, iv := range c.IgnoredVulns {
		if iv.Used {
			filtered = append(filtered, iv)
		} else {
			removed = append(removed, iv)
		}
	}

	c.IgnoredVulns = filtered

	return removed
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
