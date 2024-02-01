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
	IgnoredVulns []IgnoreEntry `toml:"IgnoredVulns"`
	LoadPath     string        `toml:"LoadPath"`
}

type IgnoreEntry struct {
	ID          string    `toml:"id"`
	IgnoreUntil time.Time `toml:"ignoreUntil"`
	Reason      string    `toml:"reason"`
}

func (c *Config) ShouldIgnore(vulnID string) (bool, IgnoreEntry) {
	index := slices.IndexFunc(c.IgnoredVulns, func(elem IgnoreEntry) bool { return elem.ID == vulnID })
	if index == -1 {
		return false, IgnoreEntry{}
	}
	ignoredLine := c.IgnoredVulns[index]
	if ignoredLine.IgnoreUntil.IsZero() {
		// If IgnoreUntil is not set, should ignore.
		return true, ignoredLine
	}
	// Should ignore if IgnoreUntil is still after current time
	// Takes timezone offsets into account if it is specified. otherwise it's using local time
	return ignoredLine.IgnoreUntil.After(time.Now()), ignoredLine
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
