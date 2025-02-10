package scanners

import "testing"

func TestLockfileScalibrMappingExists(t *testing.T) {
	t.Parallel()

	// Every lockfileExtractor should have a mapping,
	// this might not be true the other way around as some extractors are dynamically set,
	// and not present in lockfileExtractors
	for _, target := range lockfileExtractors {
		found := false
		for _, val := range lockfileExtractorMapping {
			for _, name := range val {
				if target.Name() == name {
					found = true
					break
				}
			}
		}

		if !found {
			t.Errorf("Extractor %v not found.", target)
		}
	}
}
