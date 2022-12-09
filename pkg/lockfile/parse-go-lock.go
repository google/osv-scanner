package lockfile

import (
	"fmt"
	"golang.org/x/mod/modfile"
	"os"
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
	lockfileContents, err := os.ReadFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	parsedLockfile, err := modfile.Parse(pathToLockfile, lockfileContents, nil)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not parse %s: %w", pathToLockfile, err)
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
		packages[replace.Old.Path+"@"+replace.Old.Version] = PackageDetails{
			Name:      replace.New.Path,
			Version:   strings.TrimPrefix(replace.New.Version, "v"),
			Ecosystem: GoEcosystem,
			CompareAs: GoEcosystem,
		}
	}

	return pkgDetailsMapToSlice(deduplicatePackages(packages)), nil
}
