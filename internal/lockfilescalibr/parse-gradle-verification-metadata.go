package lockfilescalibr

import (
	"context"
	"encoding/xml"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

type GradleVerificationMetadataFile struct {
	Components []struct {
		Group   string `xml:"group,attr"`
		Name    string `xml:"name,attr"`
		Version string `xml:"version,attr"`
	} `xml:"components>component"`
}

type GradleVerificationMetadataExtractor struct{}

// Name of the extractor
func (e GradleVerificationMetadataExtractor) Name() string { return "go/gomod" }

// Version of the extractor
func (e GradleVerificationMetadataExtractor) Version() int { return 0 }

func (e GradleVerificationMetadataExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e GradleVerificationMetadataExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(filepath.Dir(path)) == "gradle" && filepath.Base(path) == "verification-metadata.xml"
}

func (e GradleVerificationMetadataExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *GradleVerificationMetadataFile

	err := xml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	pkgs := make([]*Inventory, 0, len(parsedLockfile.Components))

	for _, component := range parsedLockfile.Components {
		pkgs = append(pkgs, &Inventory{
			Name:      component.Group + ":" + component.Name,
			Version:   component.Version,
			Locations: []string{input.Path},
		})
	}

	return pkgs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e GradleVerificationMetadataExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeMaven,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e GradleVerificationMetadataExtractor) ToCPEs(i *Inventory) ([]string, error) {
	return []string{}, nil
}

func (e GradleVerificationMetadataExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case GradleVerificationMetadataExtractor:
		return string(MavenEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = GradleVerificationMetadataExtractor{}
