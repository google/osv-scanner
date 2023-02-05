package lockfile

import (
	"fmt"
	"os"
)

type Diagnostics struct {
	Warnings []string
}

func (diag *Diagnostics) Warn(warn string) {
	diag.Warnings = append(diag.Warnings, warn)
}

func parseFileAndPrintDiag(pathToLockfile string, parserWithDiag PackageDetailsParserWithDiag) ([]PackageDetails, error) {
	details, diag, err := parserWithDiag(pathToLockfile)

	for _, warning := range diag.Warnings {
		_, _ = fmt.Fprintf(os.Stderr, "warning while parsing %s: %s", pathToLockfile, warning)
	}

	return details, err
}

func parseFile(pathToLockfile string, parserWithReader PackageDetailsParserWithReader) ([]PackageDetails, Diagnostics, error) {
	r, err := os.Open(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, Diagnostics{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	details, diag, err := parserWithReader(r)

	if err != nil {
		err = fmt.Errorf("error while parsing %s: %w", pathToLockfile, err)
	}

	return details, diag, err
}
