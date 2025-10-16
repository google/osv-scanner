// Package config manages the configuration for osv-scanner.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels"
)

var OSVScannerConfigName = "osv-scanner.toml"

type Manager struct {
	// Override to replace all other configs
	OverrideConfig *Config
	// Config to use if no config file is found alongside manifests
	DefaultConfig Config
	// Cache to store loaded configs
	ConfigMap map[string]Config
}

type Config struct {
	IgnoredVulns      []IgnoreEntry          `toml:"IgnoredVulns"`
	PackageOverrides  []PackageOverrideEntry `toml:"PackageOverrides"`
	GoVersionOverride string                 `toml:"GoVersionOverride"`
	// The path to config file that this config was loaded from,
	// set by the scanner after having successfully parsed the file
	LoadPath string `toml:"-"`
}

func (c *Config) UnusedIgnoredVulns() []IgnoreEntry {
	unused := make([]IgnoreEntry, 0, len(c.IgnoredVulns))

	for _, entry := range c.IgnoredVulns {
		if !entry.Used {
			unused = append(unused, entry)
		}
	}

	return unused
}

type IgnoreEntry struct {
	ID          string    `toml:"id"`
	IgnoreUntil time.Time `toml:"ignoreUntil"`
	Reason      string    `toml:"reason"`

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

func (c *Config) ShouldIgnore(vulnID string) (bool, IgnoreEntry) {
	index := slices.IndexFunc(c.IgnoredVulns, func(e IgnoreEntry) bool { return e.ID == vulnID })
	if index == -1 {
		return false, IgnoreEntry{}
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

// UseOverride updates the Manager to use the config at the given path in place
// of any other config files that would be loaded when calling Get
func (c *Manager) UseOverride(configPath string) error {
	config, configErr := tryLoadConfig(configPath)
	if configErr != nil {
		return configErr
	}
	c.OverrideConfig = &config

	return nil
}

// Get returns the appropriate config to use based on the targetPath
func (c *Manager) Get(targetPath string) Config {
	if c.OverrideConfig != nil {
		return *c.OverrideConfig
	}

	configPath, err := normalizeConfigLoadPath(targetPath)
	if err != nil {
		// TODO: This can happen when target is not a file (e.g. Docker container, git hash...etc.)
		// Figure out a more robust way to load config from non files
		// r.PrintErrorf("Can't find config path: %s\n", err)
		return Config{}
	}

	config, alreadyExists := c.ConfigMap[configPath]
	if alreadyExists {
		return config
	}

	config, configErr := tryLoadConfig(configPath)
	if configErr == nil {
		cmdlogger.Infof("Loaded filter from: %s", config.LoadPath)
	} else {
		// anything other than the config file not existing is most likely due to an invalid config file
		if !errors.Is(configErr, os.ErrNotExist) {
			cmdlogger.Errorf("Ignored invalid config file at %s because: %v", configPath, configErr)
		}
		// If config doesn't exist, use the default config
		config = c.DefaultConfig
	}
	c.ConfigMap[configPath] = config

	return config
}

func (c *Manager) GetUnusedIgnoreEntries() map[string][]IgnoreEntry {
	m := make(map[string][]IgnoreEntry)

	for _, config := range c.ConfigMap {
		unusedEntries := config.UnusedIgnoredVulns()

		if len(unusedEntries) > 0 {
			m[config.LoadPath] = unusedEntries
		}
	}

	if c.OverrideConfig != nil {
		unusedEntries := c.OverrideConfig.UnusedIgnoredVulns()

		if len(unusedEntries) > 0 {
			m[c.OverrideConfig.LoadPath] = unusedEntries
		}
	}

	return m
}

// Finds the containing folder of `target`, then appends osvScannerConfigName
func normalizeConfigLoadPath(target string) (string, error) {
	stat, err := os.Stat(target)
	if err != nil {
		return "", fmt.Errorf("failed to stat target: %w", err)
	}

	var containingFolder string
	if !stat.IsDir() {
		containingFolder = filepath.Dir(target)
	} else {
		containingFolder = target
	}
	configPath := filepath.Join(containingFolder, OSVScannerConfigName)

	return configPath, nil
}

// tryLoadConfig attempts to parse the config file at the given path as TOML,
// returning the Config object if successful or otherwise the error
func tryLoadConfig(configPath string) (Config, error) {
	config := Config{}
	m, err := toml.DecodeFile(configPath, &config)
	if err == nil {
		unknownKeys := m.Undecoded()

		if len(unknownKeys) > 0 {
			keys := make([]string, 0, len(unknownKeys))

			for _, key := range unknownKeys {
				keys = append(keys, key.String())
			}

			return Config{}, fmt.Errorf("unknown keys in config file: %s", strings.Join(keys, ", "))
		}

		config.LoadPath = configPath
		config.warnAboutDuplicates()
	}

	return config, err
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
