package lockfilescalibr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/package-url/packageurl-go"
)

type ComposerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Reference string `json:"reference"`
	} `json:"dist"`
}

type ComposerLock struct {
	Packages    []ComposerPackage `json:"packages"`
	PackagesDev []ComposerPackage `json:"packages-dev"`
}

const ComposerEcosystem Ecosystem = "Packagist"

type ComposerLockExtractor struct{}

// Name of the extractor
func (e ComposerLockExtractor) Name() string { return "php/composerlock" }

// Version of the extractor
func (e ComposerLockExtractor) Version() int { return 0 }

func (e ComposerLockExtractor) Requirements() Requirements {
	return Requirements{}
}

func (e ComposerLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "composer.lock"
}

func (e ComposerLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *ComposerLock

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make(
		[]*Inventory,
		0,
		// len cannot return negative numbers, but the types can't reflect that
		uint64(len(parsedLockfile.Packages))+uint64(len(parsedLockfile.PackagesDev)),
	)

	for _, composerPackage := range parsedLockfile.Packages {
		packages = append(packages, &Inventory{
			Name:      composerPackage.Name,
			Version:   composerPackage.Version,
			Locations: []string{input.Path},
			SourceCode: &SourceCodeIdentifier{
				Commit: composerPackage.Dist.Reference,
			},
			Metadata: DepGroupMetadata{
				DepGroupVals: []string{},
			},
		})
	}

	for _, composerPackage := range parsedLockfile.PackagesDev {
		packages = append(packages, &Inventory{
			Name:      composerPackage.Name,
			Version:   composerPackage.Version,
			Locations: []string{input.Path},
			SourceCode: &SourceCodeIdentifier{
				Commit: composerPackage.Dist.Reference,
			},
			Metadata: DepGroupMetadata{
				DepGroupVals: []string{"dev"},
			},
		})
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e ComposerLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeComposer,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e ComposerLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e ComposerLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case ComposerLockExtractor:
		return string(ComposerEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = ComposerLockExtractor{}
