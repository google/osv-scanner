package lockfilescalibr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/maps"
)

type PipenvPackage struct {
	Version string `json:"version"`
}

type PipenvLock struct {
	Packages    map[string]PipenvPackage `json:"default"`
	PackagesDev map[string]PipenvPackage `json:"develop"`
}

const PipenvEcosystem = "PyPI"

type PipenvLockExtractor struct{}

// Name of the extractor
func (e PipenvLockExtractor) Name() string { return "python/piplock" }

// Version of the extractor
func (e PipenvLockExtractor) Version() int { return 0 }

func (e PipenvLockExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e PipenvLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "Pipfile.lock"
}

func (e PipenvLockExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *PipenvLock

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	details := make(map[string]*extractor.Inventory)

	addPkgDetails(details, parsedLockfile.Packages, "")
	addPkgDetails(details, parsedLockfile.PackagesDev, "dev")

	for key := range details {
		details[key].Locations = []string{input.Path}
	}

	return maps.Values(details), nil
}

func addPkgDetails(details map[string]*extractor.Inventory, packages map[string]PipenvPackage, group string) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		version := pipenvPackage.Version[2:]

		// Because in the caller, prod packages are added first,
		// if it also exists in dev we don't want to add it to dev group
		if _, ok := details[name+"@"+version]; !ok {
			groupSlice := []string{}
			if group != "" {
				groupSlice = []string{group}
			}

			inv := &extractor.Inventory{
				Name:    name,
				Version: version,
				Metadata: othermetadata.DepGroupMetadata{
					DepGroupVals: groupSlice,
				},
			}

			details[name+"@"+version] = inv
		}
	}
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e PipenvLockExtractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypePyPi,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e PipenvLockExtractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e PipenvLockExtractor) Ecosystem(i *extractor.Inventory) (string, error) {
	switch i.Extractor.(type) {
	case PipenvLockExtractor:
		return string(PipenvEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ filesystem.Extractor = PipenvLockExtractor{}
