package output

import (
	"encoding/json"
	"io"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// PrintSPDXResults writes results to the provided writer in SPDX format
func PrintSPDXResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	doc := converter.ToSPDX23(&scalibr.ScanResult{}, converter.SPDXConfig{})

	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")

	return encoder.Encode(doc)
}
