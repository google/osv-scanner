// Package ecosystemmock provides an extractor that just returns the passed in Ecosystem string from Ecosystem()
// This is useful when manually creating an inventory so that inv.Ecosystem() returns the ecosystem you want
package ecosystemmock

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "ecosystemock"
)

type Extractor struct {
	MockEcosystem string
}

func (e Extractor) Name() string { return Name }

func (e Extractor) Version() int { return 0 }

func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

func (e Extractor) FileRequired(_ filesystem.FileAPI) bool {
	return false
}

func (e Extractor) Extract(_ context.Context, _ *filesystem.ScanInput) (inventory.Inventory, error) {
	panic("this is not a real extractor and should not be called")
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(_ *extractor.Package) *purl.PackageURL {
	return nil
}

// Ecosystem returns the OSV ecosystem ('npm') of the software extracted by this extractor.
func (e Extractor) Ecosystem(_ *extractor.Package) string {
	return e.MockEcosystem
}

var _ filesystem.Extractor = Extractor{}
