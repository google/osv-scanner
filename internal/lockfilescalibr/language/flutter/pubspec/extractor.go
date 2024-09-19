// Package pubspec extracts pubspec.lock files.
package pubspec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
)

type pubspecLockDescription struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Path string `yaml:"path"`
	Ref  string `yaml:"resolved-ref"`
}

var _ yaml.Unmarshaler = &pubspecLockDescription{}

func (pld *pubspecLockDescription) UnmarshalYAML(value *yaml.Node) error {
	var m struct {
		Name string `yaml:"name"`
		URL  string `yaml:"url"`
		Path string `yaml:"path"`
		Ref  string `yaml:"resolved-ref"`
	}

	err := value.Decode(&m)

	if err == nil {
		pld.Name = m.Name
		pld.Path = m.Path
		pld.URL = m.URL
		pld.Ref = m.Ref

		return nil
	}

	var str *string

	err = value.Decode(&str)

	if err != nil {
		return err
	}

	pld.Path = *str

	return nil
}

type pubspecLockPackage struct {
	Source      string                 `yaml:"source"`
	Description pubspecLockDescription `yaml:"description"`
	Version     string                 `yaml:"version"`
	Dependency  string                 `yaml:"dependency"`
}

type pubspecLockfile struct {
	Packages map[string]pubspecLockPackage `yaml:"packages,omitempty"`
	Sdks     map[string]string             `yaml:"sdks"`
}

const pubEcosystem string = "Pub"

// Extractor extracts flutter packages from pubspec.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "flutter/pubspec" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Flutter Pub lockfile patterns.
func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "pubspec.lock"
}

// Extract extracts packages from pubspec.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *pubspecLockfile

	err := yaml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil && !errors.Is(err, io.EOF) {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}
	if parsedLockfile == nil {
		return []*extractor.Inventory{}, nil
	}

	packages := make([]*extractor.Inventory, 0, len(parsedLockfile.Packages))

	for name, pkg := range parsedLockfile.Packages {
		pkgDetails := &extractor.Inventory{
			Name:      name,
			Version:   pkg.Version,
			Locations: []string{input.Path},
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: pkg.Description.Ref,
			},
			Metadata: othermetadata.DepGroupMetadata{
				DepGroupVals: []string{},
			},
		}
		for _, str := range strings.Split(pkg.Dependency, " ") {
			if str == "dev" {
				pkgDetails.Metadata = othermetadata.DepGroupMetadata{
					DepGroupVals: []string{"dev"},
				}

				break
			}
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypePub,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) {
	return []string{}, nil
}

// Ecosystem returns the OSV ecosystem ('Pub') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return pubEcosystem, nil
}

var _ filesystem.Extractor = Extractor{}
