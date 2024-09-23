package models

type PackageMetadataType string

const (
	PackageManagerMetadata     PackageMetadataType = "package-manager"
	IsDirectDependencyMetadata PackageMetadataType = "is-direct"
)

type PackageMetadata map[PackageMetadataType]string

func (metadata PackageMetadata) Merge(other PackageMetadata) PackageMetadata {
	if other == nil {
		return metadata
	}

	for key, value := range other {
		if _, exists := metadata[key]; !exists {
			// If the metadata does not exist, then we merge the one from PackageMetadata
			metadata[key] = value
		}
	}

	return metadata
}
