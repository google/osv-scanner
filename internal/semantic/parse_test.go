package semantic_test

import (
	"errors"
	"testing"

	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
)

func TestParse(t *testing.T) {
	t.Parallel()

	ecosystems := lockfile.KnownEcosystems()

	ecosystems = append(ecosystems, "Alpine", "Debian", "Ubuntu")

	for _, ecosystem := range ecosystems {
		_, err := semantic.Parse("", models.Ecosystem(ecosystem))

		if errors.Is(err, semantic.ErrUnsupportedEcosystem) {
			t.Errorf("'%s' is not a supported ecosystem", ecosystem)
		}
	}
}

func TestMustParse(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic - '%s'", r)
		}
	}()

	ecosystems := lockfile.KnownEcosystems()

	ecosystems = append(ecosystems, "Alpine", "Debian", "Ubuntu")

	for _, ecosystem := range ecosystems {
		semantic.MustParse("", models.Ecosystem(ecosystem))
	}
}

func TestMustParse_Panic(t *testing.T) {
	t.Parallel()

	defer func() { _ = recover() }()

	semantic.MustParse("", "<unknown>")

	// if we reached here, then we can't have panicked
	t.Errorf("function did not panic when given an unknown ecosystem")
}
