package gitlab

// Location represents the location of the vulnerability occurrence
// be it a source code line, a dependency package identifier or
// whatever else.
type Location struct {
	File            string      `json:"file,omitempty"`             // File is the path relative to the search path.
	Dependency      *Dependency `json:"dependency,omitempty"`       // Dependency is the affected package.
	OperatingSystem string      `json:"operating_system,omitempty"` // OperatingSystem is the operating system and optionally its version, separated by a semicolon: linux, debian:10, etc
	Image           string      `json:"image,omitempty"`            // Name of the Docker image
	Files           []File      `json:"files,omitempty"`            // Files where the dependency is declared.
}
