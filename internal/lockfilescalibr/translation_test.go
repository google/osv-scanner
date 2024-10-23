package lockfilescalibr

import (
	"testing"
)

func TestLockfileScalibrMappingExists(t *testing.T) {
	t.Parallel()

	for _, target := range lockfileExtractorMapping {
		found := false
		for _, ext := range lockfileExtractors {
			if target == ext.Name() {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Extractor %v not found.", target)
		}
	}
}
