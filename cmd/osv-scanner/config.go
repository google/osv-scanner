package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/exp/slices"
)

type ConfigManager struct {
	// Override to replace all other configs
	overrideConfig *Config
	// Config to use if no config file is found alongside manifests
	defaultConfig Config
	// Cache to store loaded configs
	configMap map[string]Config
}

type Config struct {
	IgnoredVulns []IgnoreEntry
	LoadPath     string
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
	c.overrideConfig = &config
	return nil
}

// Attempts to get the config
func (c *ConfigManager) Get(targetPath string) Config {
	if c.overrideConfig != nil {
		return *c.overrideConfig
	}

	configPath := normalizeConfigLoadPath(targetPath)
	config, alreadyExists := c.configMap[configPath]
	if alreadyExists {
		return config
	}

	config, configErr := tryLoadConfig(configPath)
	if configErr == nil {
		log.Printf("Loaded filter from: %s", config.LoadPath)
	} else {
		// If config doesn't exist, use the default config
		config = c.defaultConfig
	}
	c.configMap[configPath] = config

	return config
}

// Finds the containing folder of `target`, then appends osvScannerConfigName
func normalizeConfigLoadPath(target string) string {
	stat, err := os.Stat(target)
	if err != nil {
		log.Fatalf("Failed to stat target: %s", err)
	}

	var containingFolder string
	if !stat.IsDir() {
		containingFolder = filepath.Dir(target)
	} else {
		containingFolder = target
	}
	configPath := filepath.Join(containingFolder, osvScannerConfigName)
	return configPath
}

// tryLoadConfig tries to load config in `target` (or it's containing directory)
// `target` will be the key for the entry in configMap
func tryLoadConfig(configPath string) (Config, error) {
	configFile, err := os.Open(configPath)
	var config Config
	if err == nil { // File exists, and we have permission to read
		_, err := toml.NewDecoder(configFile).Decode(&config)
		if err != nil {
			log.Fatalf("Failed to read config file: %s\n", err)
		}
		config.LoadPath = configPath
		return config, nil
	}

	return Config{}, fmt.Errorf("No config file found on this path: %s", configPath)
}
