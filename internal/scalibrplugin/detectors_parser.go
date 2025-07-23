package scalibrplugin

import (
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/list"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

var detectorPresets = map[string]list.InitMap{
	"cis":         list.CIS,
	"govulncheck": list.Govulncheck,
	"untested":    list.Untested,
	"weakcreds":   list.Weakcreds,
}

func ResolveEnabledDetectors(enabledDetectors []string, disabledDetectors []string) []detector.Detector {
	detectors := make(map[string]bool)

	for i, exts := range [][]string{enabledDetectors, disabledDetectors} {
		enabled := i == 0

		for _, detectorOrPreset := range exts {
			if names, ok := detectorPresets[detectorOrPreset]; ok {
				for name := range names {
					detectors[name] = enabled
				}

				continue
			}

			detectors[detectorOrPreset] = enabled
		}
	}

	asSlice := make([]detector.Detector, 0, len(detectors))

	for name, enabled := range detectors {
		if enabled && name != "" {
			loaded, err := list.DetectorsFromName(name)

			if err != nil {
				cmdlogger.Errorf("%s", err)

				continue
			}

			asSlice = append(asSlice, loaded...)
		}
	}

	return asSlice
}
