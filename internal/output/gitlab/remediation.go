package gitlab

// Remediation holds the patch required to fix a set of vulnerability occurrences.
type Remediation struct {
	Fixes   []Ref  `json:"fixes"`   // Refs to fixed vulnerability occurrences
	Summary string `json:"summary"` // Overview of how the vulnerabilities have been fixed
	Diff    string `json:"diff"`    // Base64 encoded diff, compatible with "git apply"
}

// Ref is a reference to a vulnerability occurrence in context of the remediation.
type Ref struct {
	ID string `json:"id"` // ID of a vulnerability
}

// NewRef creates a reference to a vulnerability.
func NewRef(vuln Vulnerability) Ref {
	return Ref{
		ID: vuln.ID(),
	}
}
