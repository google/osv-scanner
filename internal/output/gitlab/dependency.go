package gitlab

// Dependency contains the information about the software dependency
// (package details, version, etc.).
type Dependency struct {
	// Direct is true if this is a direct dependency of the scanned project,
	// and not a transient (or transitive) dependency.
	Direct bool `json:"direct,omitempty"`

	Package `json:"package,omitempty"`
	Version string `json:"version,omitempty"`
}
