package lockfile

import (
	"fmt"
	"golang.org/x/mod/modfile"
	"io"
	"strings"
)

const GoEcosystem Ecosystem = "Go"

func deduplicatePackages(packages map[string]PackageDetails) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	for _, detail := range packages {
		details[detail.Name+"@"+detail.Version] = detail
	}

	return details
}

func ParseGoLock(pathToLockfile string) ([]PackageDetails, error) {
	return parseFileAndPrintDiag(pathToLockfile, ParseGoLockFile)
}

func ParseGoLockFile(pathToLockfile string) ([]PackageDetails, Diagnostics, error) {
	return parseFile(pathToLockfile, ParseGoLockWithDiagnostics)
}

func ParseGoLockWithDiagnostics(r io.Reader) ([]PackageDetails, Diagnostics, error) {
	var diag Diagnostics

	b, err := io.ReadAll(r)

	if err != nil {
		return []PackageDetails{}, diag, fmt.Errorf("could not read all: %w", err)
	}

	parsedLockfile, err := modfile.Parse("", b, nil)

	if err != nil {
		return []PackageDetails{}, diag, fmt.Errorf("could not parse: %w", err)
	}

	packages := map[string]PackageDetails{}

	for _, require := range parsedLockfile.Require {
		packages[require.Mod.Path+"@"+require.Mod.Version] = PackageDetails{
			Name:      require.Mod.Path,
			Version:   strings.TrimPrefix(require.Mod.Version, "v"),
			Ecosystem: GoEcosystem,
			CompareAs: GoEcosystem,
		}
	}

	for _, replace := range parsedLockfile.Replace {
		var replacements []string

		if replace.Old.Version == "" {
			// If the left version is omitted, all versions of the module are replaced.
			for k, pkg := range packages {
				if pkg.Name == replace.Old.Path {
					replacements = append(replacements, k)
				}
			}
		} else {
			// If a version is present on the left side of the arrow (=>),
			// only that specific version of the module is replaced
			s := replace.Old.Path + "@" + replace.Old.Version

			// A `replace` directive has no effect if the module version on the left side is not required.
			if _, ok := packages[s]; ok {
				replacements = []string{s}
			}
		}

		for _, replacement := range replacements {
			packages[replacement] = PackageDetails{
				Name:      replace.New.Path,
				Version:   strings.TrimPrefix(replace.New.Version, "v"),
				Ecosystem: GoEcosystem,
				CompareAs: GoEcosystem,
			}
		}
	}

	return pkgDetailsMapToSlice(deduplicatePackages(packages)), diag, nil
}
