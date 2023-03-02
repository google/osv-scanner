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
	// Checks if the file path is a standard recognized file name
	MatchesRecognizedFileNames(string) bool
	GetPackages(io.ReadSeeker, func(Identifier) error) error
}

var (
	ErrInvalidFormat = errors.New("invalid format")
)

var (
	Providers = []SBOMReader{
		&SPDX{},
		&CycloneDX{},
	}
)
