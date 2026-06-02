package gitlab

// FileType represents the type of dependency file.
type FileType string

const (
	// FileTypeRequirements represents a requirements file (e.g., requirements.txt).
	FileTypeRequirements FileType = "requirements"
	// FileTypeLockfile represents a lockfile (e.g., package-lock.json, yarn.lock).
	FileTypeLockfile FileType = "lockfile"
	// FileTypeGraphfile represents a graph file.
	FileTypeGraphfile FileType = "graphfile"
)

// File represents a file where a dependency is declared.
type File struct {
	Path         string   `json:"path"`                    // Path to the file.
	Type         FileType `json:"type"`                    // Type of the file.
	InRepository *bool    `json:"in_repository,omitempty"` // Whether the file exists in the repository.
}
