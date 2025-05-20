package helper

import (
	"slices"

	"github.com/google/osv-scanner/v2/internal/scalibrextract"
)

var presets = map[string][]string{
	"sbom":      scalibrextract.ExtractorsSBOMs,
	"lockfile":  scalibrextract.ExtractorsLockfiles,
	"directory": scalibrextract.ExtractorsDirectories,
	"artifact":  scalibrextract.ExtractorsArtifacts,
}

func ResolveEnabledExtractors(enabledExtractors []string, disabledExtractors []string) []string {
	toDisable := make(map[string]bool)

	for _, disabled := range disabledExtractors {
		for _, name := range presets[disabled] {
			toDisable[name] = true
		}

		toDisable[disabled] = true
	}

	extractors := make([]string, 0, len(enabledExtractors))

	for _, enabled := range enabledExtractors {
		if names, ok := presets[enabled]; ok {
			for _, name := range names {
				if _, disabled := toDisable[name]; !disabled {
					extractors = append(extractors, name)
				}
			}

			continue
		}

		if _, disabled := toDisable[enabled]; !disabled {
			extractors = append(extractors, enabled)
		}
	}

	slices.Sort(extractors)

	return extractors
}
