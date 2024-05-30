package suggest

import (
	"context"
	"errors"
	"fmt"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/internal/resolution/manifest"
)

type Options struct {
	IgnoreDev  bool     // Whether we should ignore development dependencies for updates
	NoUpdates  []string // List of packages that disallow updates
	AvoidMajor []string // List of packages that disallow major updates
}

// A PatchSuggester provides an ecosystem-specific method for 'suggesting'
// ManifestPatch for dependency updates.
type PatchSuggester interface {
	// Suggest returns the ManifestPatch required to update the dependencies to
	// a newer version based on the given options.
	// ManifestPatch includes ecosystem-specific information.
	Suggest(ctx context.Context, client resolve.Client, mf manifest.Manifest, opts Options) (manifest.ManifestPatch, error)
}

func GetSuggester(system resolve.System) (PatchSuggester, error) {
	switch system {
	case resolve.Maven:
		return &MavenSuggester{}, nil
	case resolve.NPM:
		return nil, errors.New("npm not yet supported")
	case resolve.UnknownSystem:
		return nil, errors.New("unknown system")
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %v", system)
	}
}
