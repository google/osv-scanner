package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scanner/pkg/reporter"
)

const osvScannerConfigName = "osv-scanner.toml"

type ConfigManager struct {
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
	LoadPath          string                 `toml:"LoadPath"`
	GoVersionOverride string                 `toml:"GoVersionOverride"`
}

type IgnoreEntry struct {
	ID          string    `toml:"id"`
	IgnoreUntil time.Time `toml:"ignoreUntil"`
	Reason      string    `toml:"reason"`
}

type PackageOverrideEntry struct {
	Name string `toml:"name"`
	// If the version is empty, the entry applies to all versions.
	Version        string    `toml:"version"`
	Ecosystem      string    `toml:"ecosystem"`
	Ignore         bool      `toml:"ignore"`
	License        License   `toml:"license"`
	EffectiveUntil time.Time `toml:"effectiveUntil"`
	Reason         string    `toml:"reason"`
}

type License struct {
	Override []string `toml:"override"`
}

func (c *Config) ShouldIgnore(vulnID string) (bool, IgnoreEntry) {
	index := slices.IndexFunc(c.IgnoredVulns, func(e IgnoreEntry) bool { return e.ID == vulnID })
	if index == -1 {
		return false, IgnoreEntry{}
	}
	ignoredLine := c.IgnoredVulns[index]

	return shouldIgnoreTimestamp(ignoredLine.IgnoreUntil), ignoredLine
}

func (c *Config) filterPackageVersionEntries(name string, version string, ecosystem string, condition func(PackageOverrideEntry) bool) (bool, PackageOverrideEntry) {
	index := slices.IndexFunc(c.PackageOverrides, func(e PackageOverrideEntry) bool {
		if ecosystem != e.Ecosystem || name != e.Name {
			return false
		}

		return (version == e.Version || e.Version == "") && condition(e)
	})
	if index == -1 {
		return false, PackageOverrideEntry{}
	}
	ignoredLine := c.PackageOverrides[index]

	return shouldIgnoreTimestamp(ignoredLine.EffectiveUntil), ignoredLine
}

func (c *Config) ShouldIgnorePackageVersion(name, version, ecosystem string) (bool, PackageOverrideEntry) {
	return c.filterPackageVersionEntries(name, version, ecosystem, func(e PackageOverrideEntry) bool {
		return e.Ignore
	})
}

func (c *Config) ShouldOverridePackageVersionLicense(name, version, ecosystem string) (bool, PackageOverrideEntry) {
	return c.filterPackageVersionEntries(name, version, ecosystem, func(e PackageOverrideEntry) bool {
		return len(e.License.Override) > 0
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
func (c *ConfigManager) UseOverride(configPath string) error {
	config := Config{}
	_, err := toml.DecodeFile(configPath, &config)
	if err != nil {
		return err
	}
	config.LoadPath = configPath
	c.OverrideConfig = &config

	return nil
}

// Attempts to get the config
func (c *ConfigManager) Get(r reporter.Reporter, targetPath string) Config {
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
		r.Infof("Loaded filter from: %s\n", config.LoadPath)
	} else {
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

// tryLoadConfig tries to load config in `target` (or it's containing directory)
// `target` will be the key for the entry in configMap
func tryLoadConfig(configPath string) (Config, error) {
	file, err := os.Open(configPath)
	var config Config
	if err == nil { // File exists, and we have permission to read
		defer file.Close()

		_, err := toml.NewDecoder(file).Decode(&config)
		if err != nil {
			return Config{}, fmt.Errorf("failed to parse config file: %w", err)
		}
		config.LoadPath = configPath

		return config, nil
	}

	return Config{}, fmt.Errorf("no config file found on this path: %s", configPath)
}
