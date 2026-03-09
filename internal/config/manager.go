package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

type Manager struct {
	// Override to replace all other configs
	OverrideConfig *Config
	// Config to use if no config file is found alongside manifests
	DefaultConfig Config
	// Cache to store loaded configs
	ConfigMap map[string]Config
}

// UseOverride updates the Manager to use the config at the given path in place
// of any other config files that would be loaded when calling Get
func (m *Manager) UseOverride(configPath string) error {
	config, configErr := tryLoadConfig(configPath)
	if configErr != nil {
		return configErr
	}
	m.OverrideConfig = &config

	return nil
}

// Get returns the appropriate config to use based on the targetPath
func (m *Manager) Get(targetPath string) Config {
	if m.OverrideConfig != nil {
		return *m.OverrideConfig
	}

	configPath, err := normalizeConfigLoadPath(targetPath)
	if err != nil {
		// TODO: This can happen when target is not a file (e.g. Docker container, git hash...etc.)
		// Figure out a more robust way to load config from non files
		// r.PrintErrorf("Can't find config path: %s\n", err)
		return Config{}
	}

	config, alreadyExists := m.ConfigMap[configPath]
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
		config = m.DefaultConfig
	}
	m.ConfigMap[configPath] = config

	return config
}

func (m *Manager) GetUnusedIgnoreEntries() map[string][]*IgnoreEntry {
	entries := make(map[string][]*IgnoreEntry)

	for _, config := range m.ConfigMap {
		unusedEntries := config.UnusedIgnoredVulns()

		if len(unusedEntries) > 0 {
			entries[config.LoadPath] = unusedEntries
		}
	}

	if m.OverrideConfig != nil {
		unusedEntries := m.OverrideConfig.UnusedIgnoredVulns()

		if len(unusedEntries) > 0 {
			entries[m.OverrideConfig.LoadPath] = unusedEntries
		}
	}

	return entries
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
	c, err := toml.DecodeFile(configPath, &config)
	if err == nil {
		unknownKeys := c.Undecoded()

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
