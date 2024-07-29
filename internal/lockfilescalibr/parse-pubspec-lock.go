package lockfilescalibr

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
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
)

type PubspecLockDescription struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Path string `yaml:"path"`
	Ref  string `yaml:"resolved-ref"`
}

var _ yaml.Unmarshaler = &PubspecLockDescription{}

func (pld *PubspecLockDescription) UnmarshalYAML(value *yaml.Node) error {
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

type PubspecLockPackage struct {
	Source      string                 `yaml:"source"`
	Description PubspecLockDescription `yaml:"description"`
	Version     string                 `yaml:"version"`
	Dependency  string                 `yaml:"dependency"`
}

type PubspecLockfile struct {
	Packages map[string]PubspecLockPackage `yaml:"packages,omitempty"`
	Sdks     map[string]string             `yaml:"sdks"`
}

const PubEcosystem Ecosystem = "Pub"

type PubspecLockExtractor struct{}

// Name of the extractor
func (e PubspecLockExtractor) Name() string { return "flutter/pubspec" }

// Version of the extractor
func (e PubspecLockExtractor) Version() int { return 0 }

func (e PubspecLockExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e PubspecLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "pubspec.lock"
}

func (e PubspecLockExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *PubspecLockfile

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
			Metadata: DepGroupMetadata{
				DepGroupVals: []string{},
			},
		}
		for _, str := range strings.Split(pkg.Dependency, " ") {
			if str == "dev" {
				pkgDetails.Metadata = DepGroupMetadata{
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
func (e PubspecLockExtractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypePub,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e PubspecLockExtractor) ToCPEs(i *extractor.Inventory) ([]string, error) {
	return []string{}, nil
}

func (e PubspecLockExtractor) Ecosystem(i *extractor.Inventory) (string, error) {
	switch i.Extractor.(type) {
	case PubspecLockExtractor:
		return string(PubEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ filesystem.Extractor = PubspecLockExtractor{}
