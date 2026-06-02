package gitlab

// Status represents the status of a scan, either `success` or `failure`
type Status string

const (
	// StatusSuccess is the identifier for a successful scan
	StatusSuccess Status = "success"
	// StatusFailure is the identifier for a failed scan
	StatusFailure Status = "failure"
)

// Scan contains the identifying information about a security scanner.
type Scan struct {
	Analyzer  AnalyzerDetails `json:"analyzer"`          // Analyzer describes the analyzer tool which wraps the scanner
	Scanner   ScannerDetails  `json:"scanner"`           // Scanner is an Object defining the scanner used to perform the scan
	Type      Category        `json:"type"`              // Type of the scan (container_scanning, dependency_scanning, dast, sast)
	Status    Status          `json:"status,omitempty"`  // Status is the status of the scan, either `success` or `failure`. Hardcoded to `success` for now
	StartTime string          `json:"start_time"`        // StartTime is the ISO8601 UTC time when the scan started (format: yyyy-mm-ddThh:mm:ss)
	EndTime   string          `json:"end_time"`          // EndTime is the ISO8601 UTC time when the scan finished (format: yyyy-mm-ddThh:mm:ss)
}
