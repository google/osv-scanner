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
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

const osvScannerConfigName = "osv-scanner.toml"

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

type IgnoreEntry struct {
	ID          string    `toml:"id"`
	IgnoreUntil time.Time `toml:"ignoreUntil"`
	Reason      string    `toml:"reason"`
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

func (e PackageOverrideEntry) matches(pkg models.PackageVulns) bool {
	if e.Name != "" && e.Name != pkg.Package.Name {
		return false
	}
	if e.Version != "" && e.Version != pkg.Package.Version {
		return false
	}
	if e.Ecosystem != "" && e.Ecosystem != pkg.Package.Ecosystem {
		return false
	}
	if e.Group != "" && !slices.Contains(pkg.DepGroups, e.Group) {
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

func (c *Config) filterPackageVersionEntries(pkg models.PackageVulns, condition func(PackageOverrideEntry) bool) (bool, PackageOverrideEntry) {
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
func (c *Config) ShouldIgnorePackage(pkg models.PackageVulns) (bool, PackageOverrideEntry) {
	return c.filterPackageVersionEntries(pkg, func(e PackageOverrideEntry) bool {
		return e.Ignore
	})
}

// ShouldIgnorePackageVulnerabilities determines if the given package should have its vulnerabilities ignored based on override entries in the config
func (c *Config) ShouldIgnorePackageVulnerabilities(pkg models.PackageVulns) bool {
	overrides, _ := c.filterPackageVersionEntries(pkg, func(e PackageOverrideEntry) bool {
		return e.Vulnerability.Ignore
	})

	return overrides
}

// ShouldOverridePackageLicense determines if the given package should have its license ignored or changed based on override entries in the config
func (c *Config) ShouldOverridePackageLicense(pkg models.PackageVulns) (bool, PackageOverrideEntry) {
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

// Sets the override config by reading the config file at configPath.
// Will return an error if loading the config file fails
func (c *Manager) UseOverride(r reporter.Reporter, configPath string) error {
	config, configErr := tryLoadConfig(r, configPath)
	if configErr != nil {
		return configErr
	}
	c.OverrideConfig = &config

	return nil
}

// Attempts to get the config
func (c *Manager) Get(r reporter.Reporter, targetPath string) Config {
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

	config, configErr := tryLoadConfig(r, configPath)
	if configErr == nil {
		r.Infof("Loaded filter from: %s\n", config.LoadPath)
	} else {
		// anything other than the config file not existing is most likely due to an invalid config file
		if !errors.Is(configErr, os.ErrNotExist) {
			r.Errorf("Ignored invalid config file at: %s\n", configPath)
			r.Verbosef("Config file %s is invalid because: %v\n", configPath, configErr)
		}
		// If config doesn't exist, use the default config
		config = c.DefaultConfig
	}
	c.ConfigMap[configPath] = config

	return config
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
	configPath := filepath.Join(containingFolder, osvScannerConfigName)

	return configPath, nil
}

// tryLoadConfig attempts to parse the config file at the given path as TOML,
// returning the Config object if successful or otherwise the error
func tryLoadConfig(r reporter.Reporter, configPath string) (Config, error) {
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
		config.warnAboutDuplicates(r)
	}

	return config, err
}

func (c *Config) warnAboutDuplicates(r reporter.Reporter) {
	seen := make(map[string]struct{})

	for _, vuln := range c.IgnoredVulns {
		if _, ok := seen[vuln.ID]; ok {
			r.Warnf("warning: %s has multiple ignores for %s - only the first will be used!\n", c.LoadPath, vuln.ID)
		}
		seen[vuln.ID] = struct{}{}
	}
}
