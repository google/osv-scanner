package results

import (
	"github.com/google/osv-scanner/internal/config"
	"github.com/google/osv-scanner/internal/imodels"
)

type ScanResults struct {
	PackageScanResults []imodels.PackageScanResult

	// The user parameters for the scan
	// ScanParameters

	// Scan config
	ConfigManager config.Manager

	// For container scanning, metadata including layer information
	ImageMetadata *imodels.ImageMetadata
}
