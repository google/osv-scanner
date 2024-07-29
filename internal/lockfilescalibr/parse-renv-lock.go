package lockfilescalibr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

type RenvPackage struct {
	Package    string `json:"Package"`
	Version    string `json:"Version"`
	Repository string `json:"Repository"`
}

type RenvLockfile struct {
	Packages map[string]RenvPackage `json:"Packages"`
}

const CRANEcosystem Ecosystem = "CRAN"

type RenvLockExtractor struct{}

// Name of the extractor
func (e RenvLockExtractor) Name() string { return "r/renvlock" }

// Version of the extractor
func (e RenvLockExtractor) Version() int { return 0 }

func (e RenvLockExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e RenvLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "renv.lock"
}

func (e RenvLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *RenvLockfile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*Inventory, 0, len(parsedLockfile.Packages))

	for _, pkg := range parsedLockfile.Packages {
		// currently we only support CRAN
		if pkg.Repository != string(CRANEcosystem) {
			continue
		}

		packages = append(packages, &Inventory{
			Name:      pkg.Package,
			Version:   pkg.Version,
			Locations: []string{input.Path},
		})
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e RenvLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeCran,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e RenvLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e RenvLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case RenvLockExtractor:
		return string(CRANEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = RenvLockExtractor{}
