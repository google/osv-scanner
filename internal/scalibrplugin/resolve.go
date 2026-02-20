// Package scalibrplugin provides functions related to resolving scalibr plugins
package scalibrplugin

import (
	"fmt"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/list"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

func resolveFromName(name string) (plugin.Plugin, error) {
	plug, err := list.FromName(name, nil)

	if err == nil {
		return plug, nil
	}

	switch name {
	// Javascript
	case nodemodules.Name:
		return nodemodules.New(&cpb.PluginConfig{})
	// Directories
	case vendored.Name:
		return vendored.New(&cpb.PluginConfig{})
	case gitrepo.Name:
		return gitrepo.New(&cpb.PluginConfig{})
	case osvscannerjson.Name:
		return osvscannerjson.New(&cpb.PluginConfig{})
	default:
		return nil, fmt.Errorf("not an exact name for a plugin: %q", name)
	}
}

func Resolve(enabledPlugins []string, disabledPlugins []string) []plugin.Plugin {
	plugins := make(map[string]bool)

	for i, exts := range [][]string{enabledPlugins, disabledPlugins} {
		enabled := i == 0

		for _, pluginOrPreset := range exts {
			wasAPreset := false
			if names, ok := ExtractorPresets[pluginOrPreset]; ok {
				for name := range names {
					plugins[name] = enabled
				}
				wasAPreset = true
			}

			if names, ok := detectorPresets[pluginOrPreset]; ok {
				for name := range names {
					plugins[name] = enabled
				}
				wasAPreset = true
			}

			if names, ok := annotatorPresets[pluginOrPreset]; ok {
				for name := range names {
					plugins[name] = enabled
				}
				wasAPreset = true
			}

			if names, ok := enricherPresets[pluginOrPreset]; ok {
				for name := range names {
					plugins[name] = enabled
				}
				wasAPreset = true
			}

			if !wasAPreset {
				plugins[pluginOrPreset] = enabled
			}
		}
	}

	asSlice := make([]plugin.Plugin, 0, len(plugins))

	for name, value := range plugins {
		if name != "" && value {
			plug, err := resolveFromName(name)

			if err != nil {
				cmdlogger.Errorf("%s", err)

				continue
			}

			asSlice = append(asSlice, plug)
		}
	}

	return asSlice
}
