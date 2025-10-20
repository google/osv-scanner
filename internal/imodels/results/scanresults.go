// Package results defines the data structures for scan results.
package results

import (
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
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
	ImageMetadata *spb.ContainerImageMetadata

	GenericFindings []*inventory.GenericFinding
}
