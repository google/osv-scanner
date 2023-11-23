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

// Reader is an interface for all SBOM providers.
type Reader interface {
	Name() string
	// MatchesRecognizedFileNames checks if the file path is a standard recognized file name
	MatchesRecognizedFileNames(path string) bool
	GetPackages(r io.ReadSeeker, callback func(Identifier) error) error
}

var (
	Providers = []Reader{
		&SPDX{},
		&CycloneDX{},
	}
)

type InvalidFormatError struct {
	Msg  string
	Errs []error
}

func (e InvalidFormatError) Error() string {
	errStrings := make([]string, 0, len(e.Errs))
	for _, e := range e.Errs {
		errStrings = append(errStrings, "\t"+e.Error())
	}

	return fmt.Sprintf("%s:\n%s", e.Msg, strings.Join(errStrings, "\n"))
}
