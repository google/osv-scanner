package gitlab

// Report is the output of an analyzer.
type Report struct {
	Version         Version         `json:"version"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Remediations    []Remediation   `json:"remediations,omitempty"`
	Scan            Scan            `json:"scan"`
}
