// Package results defines the data structures for scan results.
package results

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/imodels"
)

// ScanResults represents the complete results of a scan.
// This includes information that affect multiple packages.
type ScanResults struct {
	PackageScanResults []imodels.PackageScanResult

	// TODO(v2): Temporarily commented out until ScanParameters is moved
	// to a shared package to avoid cyclic dependencies
	// The user parameters for the scan
	// ScanParameters

	// Scan config
	ConfigManager config.Manager

	// For container scanning, metadata including layer information
	ImageMetadata *extractor.ContainerImageMetadata

	OS string

	GenericFindings []*inventory.GenericFinding
}
