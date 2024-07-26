package lockfilescalibr

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/package-url/packageurl-go"
)

type cargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type cargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []cargoLockPackage `toml:"package"`
}

const CargoEcosystem Ecosystem = "crates.io"

type CargoLockExtractor struct{}

// Name of the extractor
func (e CargoLockExtractor) Name() string { return "rust/cargolock" }

// Version of the extractor
func (e CargoLockExtractor) Version() int { return 0 }

func (e CargoLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	// TODO: File size check?
	return filepath.Base(path) == "Cargo.lock"
}

func (e CargoLockExtractor) Requirements() Requirements {
	return Requirements{}
}

func (e CargoLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *cargoLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*Inventory, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		packages = append(packages, &Inventory{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Locations: []string{input.Path},
		})
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e CargoLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeCargo,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e CargoLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e CargoLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case CargoLockExtractor:
		return string(CargoEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = CargoLockExtractor{}
