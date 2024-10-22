package lockfile

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/mod/modfile"
)

const GoEcosystem Ecosystem = "Go"

func deduplicatePackages(packages map[string]PackageDetails) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	for _, detail := range packages {
		details[detail.Name+"@"+detail.Version] = detail
	}

	return details
}

type GoLockExtractor struct{}

func (e GoLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "go.mod"
}

func (e GoLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *modfile.File

	b, err := io.ReadAll(f)

	if err == nil {
		parsedLockfile, err = modfile.Parse(f.Path(), b, nil)
	}

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
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

	if parsedLockfile.Go != nil && parsedLockfile.Go.Version != "" {
		packages["stdlib"] = PackageDetails{
			Name:      "stdlib",
			Version:   parsedLockfile.Go.Version,
			Ecosystem: GoEcosystem,
			CompareAs: GoEcosystem,
		}
	}

	return maps.Values(deduplicatePackages(packages)), nil
}

var _ Extractor = GoLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("go.mod", GoLockExtractor{})
}

// Deprecated: use GoLockExtractor.Extract instead
func ParseGoLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, GoLockExtractor{})
}
