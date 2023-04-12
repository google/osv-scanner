package sbom

import (
	"fmt"
	"io"
	"strings"
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
	Providers = []SBOMReader{
		&SPDX{},
		&CycloneDX{},
	}
)

type InvalidFormatError struct {
	msg  string
	errs []error
}

func (e InvalidFormatError) Error() string {
	errStrings := make([]string, 0, len(e.errs))
	for _, e := range e.errs {
		errStrings = append(errStrings, "\t"+e.Error())
	}

	return fmt.Sprintf("%s:\n%s", e.msg, strings.Join(errStrings, "\n"))
}
