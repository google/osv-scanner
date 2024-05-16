package lockfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"

	"golang.org/x/mod/module"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/internal/semantic"
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

func defaultNonCanonicalVersions(path, version string) (string, error) {
	resolvedVersion := module.CanonicalVersion(version)

	// If the resolvedVersion is not canonical, we try to find the major resolvedVersion in the path and report that
	if resolvedVersion == "" {
		_, pathMajor, ok := module.SplitPathVersion(path)
		if ok {
			resolvedVersion = module.PathMajorPrefix(pathMajor)
		}
	}

	if resolvedVersion == "" {
		// If it is still not resolved, we default on 0.0.0 as we do with other package managers
		_, _ = fmt.Fprintf(os.Stderr, "%s@%s is not a canonical path, defaulting to v0.0.0\n", path, resolvedVersion)
		return "v0.0.0", nil
	}

	return resolvedVersion, nil
}

func (e GoLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "go.mod"
}

func (e GoLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *modfile.File

	b, err := io.ReadAll(f)
	lines := fileposition.BytesToLines(b)

	if err == nil {
		parsedLockfile, err = modfile.Parse(f.Path(), b, defaultNonCanonicalVersions)
	}

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := map[string]PackageDetails{}

	for _, require := range parsedLockfile.Require {
		var start = require.Syntax.Start
		var end = require.Syntax.End
		block := lines[start.Line-1 : end.Line]
		version := strings.TrimPrefix(require.Mod.Version, "v")
		name := require.Mod.Path

		packages[require.Mod.Path+"@"+require.Mod.Version] = PackageDetails{
			Name:      name,
			Version:   version,
			Ecosystem: GoEcosystem,
			CompareAs: GoEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: start.Line, End: end.Line},
				Column: models.Position{Start: start.LineRune, End: end.LineRune},
			},
			VersionLocation: fileposition.ExtractStringPositionInBlock(block, version, start.Line),
			NameLocation:    fileposition.ExtractStringPositionInBlock(block, name, start.Line),
		}
	}

	for _, replace := range parsedLockfile.Replace {
		var start = replace.Syntax.Start
		var end = replace.Syntax.End
		block := lines[start.Line-1 : end.Line]
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
			version := strings.TrimPrefix(replace.New.Version, "v")
			name := replace.New.Path

			if len(version) == 0 {
				// There is no version specified on the replacement, it means the artifact is directly accessible
				// the package itself will then be scanned so there is no need to keep it
				delete(packages, replacement)
				continue
			}
			packages[replacement] = PackageDetails{
				Name:      name,
				Version:   version,
				Ecosystem: GoEcosystem,
				CompareAs: GoEcosystem,
				BlockLocation: models.FilePosition{
					Line:   models.Position{Start: start.Line, End: end.Line},
					Column: models.Position{Start: start.LineRune, End: end.LineRune},
				},
				VersionLocation: fileposition.ExtractStringPositionInBlock(block, version, start.Line),
				NameLocation:    fileposition.ExtractStringPositionInBlock(block, name, start.Line),
			}
		}
	}

	if parsedLockfile.Go != nil && parsedLockfile.Go.Version != "" {
		v := semantic.ParseSemverLikeVersion(parsedLockfile.Go.Version, 3)

		goVersion := fmt.Sprintf(
			"%d.%d.%d",
			v.Components.Fetch(0),
			v.Components.Fetch(1),
			v.Components.Fetch(2),
		)

		packages["stdlib"] = PackageDetails{
			Name:      "stdlib",
			Version:   goVersion,
			Ecosystem: GoEcosystem,
			CompareAs: GoEcosystem,
		}
	}

	return pkgDetailsMapToSlice(deduplicatePackages(packages)), nil
}

var _ Extractor = GoLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("go.mod", GoLockExtractor{})
}

func ParseGoLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, GoLockExtractor{})
}
