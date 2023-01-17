package semantic_test

import (
	"errors"
	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	ecosystems := lockfile.KnownEcosystems()

	for _, ecosystem := range ecosystems {
		_, err := semantic.Parse("", ecosystem)

		if errors.Is(err, semantic.ErrUnsupportedEcosystem) {
			t.Errorf("'%s' is not a supported ecosystem", ecosystem)
		}
	}
}
