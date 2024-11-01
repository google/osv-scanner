// Package osvscannerjson extracts osv-scanner's json output.
package osvscannerjson

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/pkg/models"
)

// Extractor extracts osv packages from osv-scanner json output.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return "osv/osvscannerjson" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired never returns true, as this is for the osv-scanner json output.
func (e Extractor) FileRequired(_ string, _ fs.FileInfo) bool {
	return false
}

// Extract extracts packages from yarn.lock files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	parsedResults := models.VulnerabilityResults{}
	err := json.NewDecoder(input.Reader).Decode(&parsedResults)

	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := []*extractor.Inventory{}
	for _, res := range parsedResults.Results {
		for _, pkg := range res.Packages {
			inventory := extractor.Inventory{
				Name:    pkg.Package.Name,
				Version: pkg.Package.Version,
				Metadata: Metadata{
					Ecosystem:  pkg.Package.Ecosystem,
					SourceInfo: res.Source,
				},
				Locations: []string{input.Path},
			}
			if pkg.Package.Commit != "" {
				inventory.SourceCode = &extractor.SourceCodeIdentifier{
					Commit: pkg.Package.Commit,
				}
			}

			packages = append(packages, &inventory)
		}
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(_ *extractor.Inventory) *purl.PackageURL {
	// TODO: support purl conversion
	return nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(_ *extractor.Inventory) []string { return []string{} }

// Ecosystem returns the OSV ecosystem ('npm') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return i.Metadata.(Metadata).Ecosystem
}

var _ filesystem.Extractor = Extractor{}
