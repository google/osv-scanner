package nodemodules

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/nodemodules"
)

type Extractor struct {
	actualExtractor packagelockjson.Extractor
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true for .package-lock.json files under node_modules
func (e Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	return filepath.Base(filepath.Dir(fapi.Path())) == "node_modules" && filepath.Base(fapi.Path()) == ".package-lock.json"
}

// Extract extracts packages from yarn.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return e.actualExtractor.Extract(ctx, input)
}

var _ filesystem.Extractor = Extractor{}
