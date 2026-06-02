package gitlab

// Category is an identifier of the security scanning tool
type Category string

const (
	// CategoryDependencyScanning is the identifier for "Dependency Scanning" vulnerability category
	CategoryDependencyScanning Category = "dependency_scanning"
	// CategoryContainerScanning is the identifier for "Container Scanning" vulnerability category
	CategoryContainerScanning Category = "container_scanning"
)
