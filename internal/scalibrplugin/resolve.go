package scalibrplugin

import (
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/list"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

func Resolve(enabledPlugins []string, disabledPlugins []string) []plugin.Plugin {
	plugins := make(map[string]bool)

	for i, exts := range [][]string{enabledPlugins, disabledPlugins} {
		enabled := i == 0

		for _, pluginOrPreset := range exts {
			if names, ok := ExtractorPresets[pluginOrPreset]; ok {
				for name := range names {
					plugins[name] = enabled
				}

				continue
			}

			if names, ok := detectorPresets[pluginOrPreset]; ok {
				for name := range names {
					plugins[name] = enabled
				}

				continue
			}

			plugins[pluginOrPreset] = enabled
		}
	}

	asSlice := make([]plugin.Plugin, 0, len(plugins))

	for name, value := range plugins {
		if name != "" && value {
			plug, err := list.FromName(name)

			if err != nil {
				plug, err = BuildExtractor(name)
			}

			if err != nil {
				cmdlogger.Errorf("%s", err)

				continue
			}

			asSlice = append(asSlice, plug)
		}
	}

	return asSlice
}
