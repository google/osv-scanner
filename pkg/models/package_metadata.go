package models

type PackageMetadataType string

const (
	PackageManagerMetadata     PackageMetadataType = "package-manager"
	IsDirectDependencyMetadata PackageMetadataType = "is-direct"
)

type PackageMetadata map[PackageMetadataType]string
