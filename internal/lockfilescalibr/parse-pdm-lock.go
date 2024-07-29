package lockfilescalibr

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

type PdmLockPackage struct {
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Groups   []string `toml:"groups"`
	Revision string   `toml:"revision"`
}

type PdmLockFile struct {
	Version  string           `toml:"lock-version"`
	Packages []PdmLockPackage `toml:"package"`
}

const PdmEcosystem = PipEcosystem

type PdmLockExtractor struct{}

// Name of the extractor
func (e PdmLockExtractor) Name() string { return "python/pdm" }

// Version of the extractor
func (e PdmLockExtractor) Version() int { return 0 }

func (e PdmLockExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e PdmLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "pdm.lock"
}

func (e PdmLockExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockFile *PdmLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockFile)
	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}
	packages := make([]*extractor.Inventory, 0, len(parsedLockFile.Packages))

	for _, pkg := range parsedLockFile.Packages {
		details := &extractor.Inventory{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Locations: []string{input.Path},
		}

		depGroups := []string{}

		var optional = true
		for _, gr := range pkg.Groups {
			if gr == "dev" {
				depGroups = append(depGroups, "dev")
				optional = false
			} else if gr == "default" {
				optional = false
			}
		}
		if optional {
			depGroups = append(depGroups, "optional")
		}

		details.Metadata = DepGroupMetadata{
			DepGroupVals: depGroups,
		}

		if pkg.Revision != "" {
			details.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: pkg.Revision,
			}
		}

		packages = append(packages, details)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e PdmLockExtractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypePyPi,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e PdmLockExtractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e PdmLockExtractor) Ecosystem(i *extractor.Inventory) (string, error) {
	switch i.Extractor.(type) {
	case PdmLockExtractor:
		return string(PdmEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ filesystem.Extractor = PdmLockExtractor{}
