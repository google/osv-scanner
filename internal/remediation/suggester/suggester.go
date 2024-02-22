package suggester

import (
	"context"
	"fmt"

	"deps.dev/util/resolve"
)

type SuggestOptions struct {
	NoMajorUpdates bool
}

// A VersionSuggester provides an ecosystem-specific method for 'suggesting'
// the latest version of a dependency based on the given options.
type VersionSuggester interface {
	Suggest(ctx context.Context, client resolve.Client, req resolve.RequirementVersion, opts SuggestOptions) (resolve.RequirementVersion, error)
}

func GetSuggester(system resolve.System) (VersionSuggester, error) {
	switch system {
	case resolve.Maven:
		return &MavenSuggester{}, nil
	case resolve.NPM:
		return nil, fmt.Errorf("npm not yet supported")
	case resolve.UnknownSystem:
		return nil, fmt.Errorf("unknown system")
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %v", system)
	}
}
