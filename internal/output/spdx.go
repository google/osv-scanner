package output

import (
	"encoding/json"
	"io"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/converter/spdx"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// PrintSPDXResults writes results to the provided writer in SPDX format
func PrintSPDXResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	scanResult := &scalibr.ScanResult{}

	for _, source := range vulnResult.Results {
		for _, pkg := range source.Packages {
			scanResult.Inventory.Packages = append(scanResult.Inventory.Packages, pkg.Package.Inventory)
		}
	}

	// TODO(#1783): Allow user configuration
	doc := spdx.ToSPDX23(scanResult, spdx.Config{})

	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")

	return encoder.Encode(doc)
}
