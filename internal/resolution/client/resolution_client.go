package client

import (
	"context"

	"deps.dev/util/resolve"
)

type ResolutionClient interface {
	resolve.Client
	// WriteCache writes a manifest-specific resolution cache.
	WriteCache(filepath string) error
	// LoadCache loads a manifest-specific resolution cache.
	LoadCache(filepath string) error
	// PreFetch loads cache, then makes and caches likely queries needed for resolving a package with a list of requirements
	PreFetch(ctx context.Context, requirements []resolve.RequirementVersion, manifestPath string)
}
