package lockfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"golang.org/x/exp/maps"

	"golang.org/x/mod/module"

	"github.com/google/osv-scanner/pkg/models"

	"golang.org/x/mod/modfile"
)

const GoEcosystem Ecosystem = "Go"
const unknownVersion = "v0.0.0-unresolved-version"

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
		_, _ = fmt.Fprintf(os.Stderr, "%s@%s is not a canonical path, defaulting to %s\n", path, resolvedVersion, unknownVersion)
		return unknownVersion, nil
	}

	return resolvedVersion, nil
}

func extractLocations(block []string, start modfile.Position, end modfile.Position, path string, name string, version string) (models.FilePosition, *models.FilePosition, *models.FilePosition) {
	blockLocation := models.FilePosition{
		Line:     models.Position{Start: start.Line, End: end.Line},
		Column:   models.Position{Start: start.LineRune, End: end.LineRune},
		Filename: path,
	}

	nameLocation := fileposition.ExtractStringPositionInBlock(block, name, start.Line)
	if nameLocation != nil {
		nameLocation.Filename = path
	}

	versionLocation := fileposition.ExtractStringPositionInBlock(block, version, start.Line)
	if versionLocation != nil {
		versionLocation.Filename = path
	}

	return blockLocation, nameLocation, versionLocation
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
		name := require.Mod.Path
		version := strings.TrimPrefix(require.Mod.Version, "v")

		if require.Mod.Version == unknownVersion {
			version = ""
		}

		blockLocation, nameLocation, versionLocation := extractLocations(block, start, end, f.Path(), name, version)
		packages[require.Mod.Path+"@"+require.Mod.Version] = PackageDetails{
			Name:            name,
			Version:         version,
			PackageManager:  models.Golang,
			Ecosystem:       GoEcosystem,
			CompareAs:       GoEcosystem,
			BlockLocation:   blockLocation,
			NameLocation:    nameLocation,
			VersionLocation: versionLocation,
			IsDirect:        !require.Indirect,
		}
	}

	for _, replace := range parsedLockfile.Replace {
		var start = replace.Syntax.Start
		var end = replace.Syntax.End
		block := lines[start.Line-1 : end.Line]
		var replacements []string

		isLocalFile := !hasHostnamePrefix(replace.New.Path)

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

			if replace.New.Version == unknownVersion {
				version = ""
			}

			blockLocation, nameLocation, versionLocation := extractLocations(block, start, end, f.Path(), name, version)

			if isLocalFile {
				// The replacement is a local file path, we keep the original package name and drop everything specific to the replacement
				name = replace.Old.Path
				version = ""
				versionLocation = nil
				nameLocation = nil
			}

			packages[replacement] = PackageDetails{
				Name:            name,
				Version:         version,
				PackageManager:  models.Golang,
				Ecosystem:       GoEcosystem,
				CompareAs:       GoEcosystem,
				BlockLocation:   blockLocation,
				VersionLocation: versionLocation,
				NameLocation:    nameLocation,
				IsDirect:        packages[replacement].IsDirect,
			}
		}
	}

	if parsedLockfile.Go != nil && parsedLockfile.Go.Version != "" {
		packages["stdlib"] = PackageDetails{
			Name:           "stdlib",
			Version:        parsedLockfile.Go.Version,
			PackageManager: models.Golang,
			Ecosystem:      GoEcosystem,
			CompareAs:      GoEcosystem,
			BlockLocation: models.FilePosition{
				Filename: f.Path(),
			},
			IsDirect: true,
		}
	}

	return maps.Values(deduplicatePackages(packages)), nil
}

var _ Extractor = GoLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("go.mod", GoLockExtractor{})
}

func ParseGoLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, GoLockExtractor{})
}

func hasHostnamePrefix(path string) bool {
	matcher := cachedregexp.MustCompile("^(\\w+:\\/\\/)?\\w+\\.\\w+.*")

	return matcher.MatchString(path)
}
