package helper

import (
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/list"
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

	// todo: rethink this life choice...
	for name, enabled := range detectors {
		if name != "" && enabled {
			for _, detectorsInPreset := range detectorPresets {
				for detectorName, detectorInits := range detectorsInPreset {
					if name == detectorName {
						for _, detectorInit := range detectorInits {
							asSlice = append(asSlice, detectorInit())
						}
					}
				}
			}
		}
	}

	return asSlice
}
