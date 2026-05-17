// Package scalibrplugin provides functions related to resolving scalibr plugins
package scalibrplugin

import (
	"fmt"
	"maps"
	"slices"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/list"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

func resolveFromName(name string, cfg *cpb.PluginConfig) (plugin.Plugin, error) {
	plug, err := list.FromName(name, cfg)

	if err == nil {
		return plug, nil
	}

	switch name {
	// Javascript
	case nodemodules.Name:
		return nodemodules.New(cfg)
	// Directories
	case vendored.Name:
		return vendored.New(cfg)
	case gitrepo.Name:
		return gitrepo.New(cfg)
	case osvscannerjson.Name:
		return osvscannerjson.New(cfg)
	default:
		return nil, fmt.Errorf("not an exact name for a plugin: %q", name)
	}
}

func Resolve(enabledPlugins []string, disabledPlugins []string, cfg *cpb.PluginConfig) []plugin.Plugin {
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
			plug, err := resolveFromName(name, cfg)

			if err != nil {
				cmdlogger.Errorf("%s", err)

				// mark the plugin as disabled in case
				// it is required by any other plugins
				plugins[name] = false

				continue
			}

			asSlice = append(asSlice, plug)
		}
	}

	return filterPluginsMissingRequiredPlugins(plugins, asSlice)
}

func filterPluginsMissingRequiredPlugins(pluginStatues map[string]bool, loaded []plugin.Plugin) []plugin.Plugin {
	plugins := make([]plugin.Plugin, 0, len(loaded))

	for _, plug := range loaded {
		en, ok := plug.(enricher.Enricher)

		// if the "loaded" status of any plugin required by an enricher "contains" false,
		// then that plugin is disabled and so the enricher requirements are not met
		if ok && slices.ContainsFunc(en.RequiredPlugins(), func(name string) bool {
			return !pluginStatues[name]
		}) {
			continue
		}

		plugins = append(plugins, plug)
	}

	return plugins
}

func sortedPresetNames[T any](presets map[string]T) []string {
	names := slices.Collect(maps.Keys(presets))
	slices.Sort(names)

	return names
}

func sortedNestedPluginNames[T any](presets map[string]map[string]T) []string {
	seen := map[string]struct{}{}

	for _, preset := range presets {
		for name := range preset {
			seen[name] = struct{}{}
		}
	}

	names := slices.Collect(maps.Keys(seen))
	slices.Sort(names)

	return names
}

func ExtractorPresetNames() []string {
	return sortedPresetNames(ExtractorPresets)
}

func DetectorPresetNames() []string {
	return sortedPresetNames(detectorPresets)
}

func AnnotatorPresetNames() []string {
	return sortedPresetNames(annotatorPresets)
}

func EnricherPresetNames() []string {
	return sortedPresetNames(enricherPresets)
}

func PluginNames() []string {
	seen := map[string]struct{}{}

	for _, name := range sortedNestedPluginNames(ExtractorPresets) {
		seen[name] = struct{}{}
	}
	for _, name := range sortedNestedPluginNames(detectorPresets) {
		seen[name] = struct{}{}
	}
	for _, name := range sortedNestedPluginNames(annotatorPresets) {
		seen[name] = struct{}{}
	}
	for _, name := range sortedNestedPluginNames(enricherPresets) {
		seen[name] = struct{}{}
	}

	names := slices.Collect(maps.Keys(seen))
	slices.Sort(names)

	return names
}
