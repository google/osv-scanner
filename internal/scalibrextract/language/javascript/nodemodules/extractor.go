package nodemodules

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type Extractor struct {
	actualExtractor packagelockjson.Extractor
}

var _ filesystem.Extractor = Extractor{}

// Name of the extractor.
func (e Extractor) Name() string { return "javascript/nodemodules" }

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
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	return e.actualExtractor.Extract(ctx, input)
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return e.actualExtractor.ToPURL(i)
}

// Ecosystem returns the OSV ecosystem ('npm') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return e.actualExtractor.Ecosystem(i)
}

var _ filesystem.Extractor = Extractor{}
