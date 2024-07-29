package gomod

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/maps"
	"golang.org/x/mod/modfile"
)

const GoEcosystem string = "Go"

// Extractor extracts go packages from a go.mod file,
// including the stdlib version by using the top level go version
//
// The output is not sorted and will not be in a consistent order
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "go/gomod" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

func (e Extractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "go.mod"
}

func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *modfile.File

	b, err := io.ReadAll(input.Reader)

	if err == nil {
		parsedLockfile, err = modfile.Parse(input.Path, b, nil)
	}

	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := map[string]*extractor.Inventory{}

	for _, require := range parsedLockfile.Require {
		packages[require.Mod.Path+"@"+require.Mod.Version] = &extractor.Inventory{
			Name:      require.Mod.Path,
			Version:   strings.TrimPrefix(require.Mod.Version, "v"),
			Locations: []string{input.Path},
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
			packages[replacement] = &extractor.Inventory{
				Name:      replace.New.Path,
				Version:   strings.TrimPrefix(replace.New.Version, "v"),
				Locations: []string{input.Path},
			}
		}
	}

	if parsedLockfile.Go != nil && parsedLockfile.Go.Version != "" {
		packages["stdlib"] = &extractor.Inventory{
			Name:      "stdlib",
			Version:   parsedLockfile.Go.Version,
			Locations: []string{input.Path},
		}
	}

	return maps.Values(deduplicatePackages(packages)), nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeGolang,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return GoEcosystem, nil
}

var _ filesystem.Extractor = Extractor{}

func deduplicatePackages(packages map[string]*extractor.Inventory) map[string]*extractor.Inventory {
	details := map[string]*extractor.Inventory{}

	for _, detail := range packages {
		details[detail.Name+"@"+detail.Version] = detail
	}

	return details
}
