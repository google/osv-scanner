package models

type PackageMetadataType string

const (
	PackageManagerMetadata     PackageMetadataType = "package-manager"
	IsDirectDependencyMetadata PackageMetadataType = "is-direct"
	IsDevDependencyMetadata    PackageMetadataType = "is-dev"
)

type PackageMetadata map[PackageMetadataType]string

func (metadata PackageMetadata) Merge(other PackageMetadata) PackageMetadata {
	if other == nil {
		return metadata
	}
	_, isDevDependency := metadata[IsDevDependencyMetadata]
	_, otherIsDevDependency := other[IsDirectDependencyMetadata]

	for key, value := range other {
		if _, exists := metadata[key]; !exists {
			// If the metadata does not exist, then we merge the one from PackageMetadata
			metadata[key] = value
		}
	}

	// For dev dependency, if one of the two is not tagged with it, we prefer to keep the prod priority
	if !isDevDependency || !otherIsDevDependency {
		delete(metadata, IsDevDependencyMetadata)
	}

	return metadata
}
