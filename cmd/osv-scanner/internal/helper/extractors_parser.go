package helper

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scanner/v2/internal/builders"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
)

var presets = map[string][]string{
	"sbom":      scalibrextract.ExtractorsSBOMs,
	"lockfile":  scalibrextract.ExtractorsLockfiles,
	"directory": scalibrextract.ExtractorsDirectories,
	"artifact":  scalibrextract.ExtractorsArtifacts,
}

func ResolveEnabledExtractors(enabledExtractors []string, disabledExtractors []string) []filesystem.Extractor {
	extractors := make(map[string]bool)

	for i, exts := range [][]string{enabledExtractors, disabledExtractors} {
		enabled := i == 0

		for _, extractorOrPreset := range exts {
			if names, ok := presets[extractorOrPreset]; ok {
				for _, name := range names {
					extractors[name] = enabled
				}

				continue
			}

			extractors[extractorOrPreset] = enabled
		}
	}

	asSlice := make([]string, 0, len(extractors))

	for name, value := range extractors {
		if name != "" && value {
			asSlice = append(asSlice, name)
		}
	}

	return builders.BuildExtractors(asSlice)
}
