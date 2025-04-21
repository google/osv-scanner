package scanners

import (
	"slices"
	"testing"
)

func TestLockfileScalibrMappingExists(t *testing.T) {
	t.Parallel()

	// Every lockfileExtractor should have a mapping,
	// this might not be true the other way around as some extractors are dynamically set,
	// and not present in lockfileExtractors
	for _, target := range buildLockfileExtractors(nil, nil) {
		found := false
		for _, names := range lockfileExtractorMapping {
			if slices.Contains(names, target.Name()) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Extractor %v not found.", target.Name())
		}
	}
}
