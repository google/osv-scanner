package gitlab

import (
	"fmt"
)

// ScannerDetails contains detailed information about the scanner
type ScannerDetails struct {
	ID      string `json:"id"`            // Unique id that identifies the scanner
	Name    string `json:"name"`          // A human readable value that identifies the scanner, not required to be unique
	URL     string `json:"url,omitempty"` // A link to more information about the scanner
	Vendor  Vendor `json:"vendor"`        // The vendor/maintainer of the scanner
	Version string `json:"version"`       // The version of the scanner
}

// AnalyzerDetails contains detailed information about the analyzer
type AnalyzerDetails = ScannerDetails

func (s ScannerDetails) String() string {
	return fmt.Sprintf("%s %s analyzer v%s", s.Vendor.Name, s.Name, s.Version)
}
