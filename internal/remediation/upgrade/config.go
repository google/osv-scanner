// Package upgrade provides functionality for parsing upgrade configurations for remediation.
package upgrade

import (
	"strings"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

type Config map[string]Level

func NewConfig() Config {
	return make(Config)
}

// Set the allowed upgrade level for a given pkg name.
// If level for pkg was previously set, sets the package to the new level and returns true.
// Otherwise, sets the package's level and returns false.
func (c Config) Set(pkg string, level Level) bool {
	_, alreadySet := c[pkg]
	c[pkg] = level

	return alreadySet
}

// SetDefault sets the default allowed upgrade level packages that weren't explicitly set.
// If default was previously set, sets the default to the new level and returns true.
// Otherwise, sets the default and returns false.
func (c Config) SetDefault(level Level) bool {
	// Empty package name is used as the default level.
	return c.Set("", level)
}

// Get the allowed Level for the given pkg name.
func (c Config) Get(pkg string) Level {
	if lvl, ok := c[pkg]; ok {
		return lvl
	}

	// Empty package name is used as the default level.
	return c[""]
}

func ParseUpgradeConfig(specs []string) Config {
	config := NewConfig()

	for _, spec := range specs {
		idx := strings.LastIndex(spec, ":")
		if idx == 0 {
			cmdlogger.Warnf("WARNING: `--upgrade-config %s` - skipping empty package name", spec)
			continue
		}
		pkg := ""
		levelStr := spec
		if idx > 0 {
			pkg = spec[:idx]
			levelStr = spec[idx+1:]
		}
		var level Level
		switch levelStr {
		case "major":
			level = Major
		case "minor":
			level = Minor
		case "patch":
			level = Patch
		case "none":
			level = None
		default:
			cmdlogger.Warnf("WARNING: `--upgrade-config %s` - invalid level string '%s'", spec, levelStr)
			continue
		}
		if config.Set(pkg, level) { // returns true if was previously set
			cmdlogger.Warnf("WARNING: `--upgrade-config %s` - config for package specified multiple times", spec)
		}
	}

	return config
}
