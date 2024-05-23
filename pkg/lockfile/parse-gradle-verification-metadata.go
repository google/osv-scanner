package lockfile

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
)

type GradleVerificationMetadataFile struct {
	Components []struct {
		Group   string `xml:"group,attr"`
		Name    string `xml:"name,attr"`
		Version string `xml:"version,attr"`
	} `xml:"components>component"`
}

type GradleVerificationMetadataExtractor struct{}

func (e GradleVerificationMetadataExtractor) ShouldExtract(path string) bool {
	return filepath.Base(filepath.Dir(path)) == "gradle" && filepath.Base(path) == "verification-metadata.xml"
}

func (e GradleVerificationMetadataExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *GradleVerificationMetadataFile

	err := xml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	pkgs := make([]PackageDetails, 0, len(parsedLockfile.Components))

	for _, component := range parsedLockfile.Components {
		pkgs = append(pkgs, PackageDetails{
			Name:      component.Group + ":" + component.Name,
			Version:   component.Version,
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
		})
	}

	return pkgs, nil
}

var _ Extractor = GradleVerificationMetadataExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("gradle/verification-metadata.xml", GradleVerificationMetadataExtractor{})
}

func ParseGradleVerificationMetadata(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, GradleVerificationMetadataExtractor{})
}
