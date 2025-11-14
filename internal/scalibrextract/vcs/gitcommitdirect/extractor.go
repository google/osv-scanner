// Package gitcommitdirect provides an dummy extractor that returns a preset list of commits
package gitcommitdirect

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "vcs/gitcommitdirect"
)

// Extractor extracts git repository hashes including submodule hashes.
// This extractor will not return an error, and will just return no results if we fail to extract
type Extractor struct {
	commits []string
}

// New returns a new instance of the extractor.
func New(commits []string) standalone.Extractor {
	return &Extractor{
		commits: commits,
	}
}

// Name of the extractor.
func (e *Extractor) Name() string { return Name }

// Version of the extractor.
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

func (e *Extractor) Extract(_ context.Context, _ *standalone.ScanInput) (inventory.Inventory, error) {
	pkgs := make([]*extractor.Package, 0, len(e.commits))
	for _, commit := range e.commits {
		pkgs = append(pkgs, &extractor.Package{
			SourceCode: &extractor.SourceCodeIdentifier{Commit: commit},
		})
	}

	return inventory.Inventory{
		Packages: pkgs,
	}, nil
}

var _ standalone.Extractor = &Extractor{}
