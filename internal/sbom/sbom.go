package sbom

import (
	"errors"
	"io"
)

// Identifier is the identifier extracted from the SBOM.
type Identifier struct {
	PURL string
}

// SBOMReader is an interface for all SBOM providers.
type SBOMReader interface {
	Name() string
	GetPackages(io.ReadSeeker, func(Identifier) error) error
}

var (
	InvalidFormat = errors.New("invalid format")
)

var (
	Providers = []SBOMReader{
		&SPDX{},
		&CycloneDX{},
	}
)
