package models

type PackageMetadataType string

const (
	PackageManagerMetadata PackageMetadataType = "package-manager"
)

type PackageMetadata map[PackageMetadataType]string
