package lockfile

import (
	"encoding/xml"
	"fmt"
	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/pkg/models"
	"os"
	"path/filepath"
)

type MavenLockDependency struct {
	XMLName    xml.Name `xml:"dependency"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Start      models.FilePosition
	End        models.FilePosition
}

type MavenLockDependencyHolder struct {
	Dependencies []MavenLockDependency `xml:"dependency"`
}

func (mld MavenLockDependency) parseResolvedVersion(version string) string {
	versionRequirementReg := cachedregexp.MustCompile(`[[(]?(.*?)(?:,|[)\]]|$)`)

	results := versionRequirementReg.FindStringSubmatch(version)

	if results == nil || results[1] == "" {
		return "0"
	}

	return results[1]
}

func (mld MavenLockDependency) resolveVersionValue(lockfile MavenLockFile) string {
	interpolationReg := cachedregexp.MustCompile(`\${(.+)}`)

	results := interpolationReg.FindStringSubmatch(mld.Version)

	// no interpolation, so just return the version as-is
	if results == nil {
		return mld.Version
	}
	if val, ok := lockfile.Properties.m[results[1]]; ok {
		return val
	}

	fmt.Fprintf(
		os.Stderr,
		"Failed to resolve version of %s: property \"%s\" could not be found for \"%s\"\n",
		mld.GroupID+":"+mld.ArtifactID,
		results[1],
		lockfile.GroupID+":"+lockfile.ArtifactID,
	)

	return "0"
}

func (mld MavenLockDependency) ResolveVersion(lockfile MavenLockFile) string {
	version := mld.resolveVersionValue(lockfile)

	return mld.parseResolvedVersion(version)
}

type MavenLockFile struct {
	XMLName             xml.Name                  `xml:"project"`
	ModelVersion        string                    `xml:"modelVersion"`
	GroupID             string                    `xml:"groupId"`
	ArtifactID          string                    `xml:"artifactId"`
	Properties          MavenLockProperties       `xml:"properties"`
	Dependencies        MavenLockDependencyHolder `xml:"dependencies"`
	ManagedDependencies MavenLockDependencyHolder `xml:"dependencyManagement>dependencies"`
}

const MavenEcosystem Ecosystem = "Maven"

type MavenLockProperties struct {
	m map[string]string
}

func (p *MavenLockProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.m = map[string]string{}

	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch tt := t.(type) {
		case xml.StartElement:
			var s string

			if err := d.DecodeElement(&s, &tt); err != nil {
				return fmt.Errorf("%w", err)
			}

			p.m[tt.Name.Local] = s

		case xml.EndElement:
			if tt.Name == start.Name {
				return nil
			}
		}
	}
}

func (dependencyHolder *MavenLockDependencyHolder) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	dependencyHolder.Dependencies = make([]MavenLockDependency, 0)
DecodingLoop:
	for {
		startLine, startColumn := decoder.InputPos()
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch elem := token.(type) {
		case xml.StartElement:
			dependency := MavenLockDependency{}
			dependency.Start = models.FilePosition{Line: startLine, Column: startColumn}
			err := decoder.DecodeElement(&dependency, &elem)
			if err != nil {
				return err
			}
			endLine, endColumn := decoder.InputPos()
			dependency.End = models.FilePosition{Line: endLine, Column: endColumn}
			dependencyHolder.Dependencies = append(dependencyHolder.Dependencies, dependency)
		case xml.EndElement:
			if elem.Name == start.Name {
				break DecodingLoop
			}
		}
	}
	return nil
}

type MavenLockExtractor struct{}

func (e MavenLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pom.xml"
}

func (e MavenLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *MavenLockFile

	err := xml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	details := map[string]PackageDetails{}

	for _, lockPackage := range parsedLockfile.Dependencies.Dependencies {
		finalName := lockPackage.GroupID + ":" + lockPackage.ArtifactID

		details[finalName] = PackageDetails{
			Name:      finalName,
			Version:   lockPackage.ResolveVersion(*parsedLockfile),
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
			Start:     lockPackage.Start,
			End:       lockPackage.End,
		}
	}

	// managed dependencies take precedent over standard dependencies
	for _, lockPackage := range parsedLockfile.ManagedDependencies.Dependencies {
		finalName := lockPackage.GroupID + ":" + lockPackage.ArtifactID

		details[finalName] = PackageDetails{
			Name:      finalName,
			Version:   lockPackage.ResolveVersion(*parsedLockfile),
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
			Start:     lockPackage.Start,
			End:       lockPackage.End,
		}
	}

	return pkgDetailsMapToSlice(details), nil
}

var _ Extractor = MavenLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("pom.xml", MavenLockExtractor{})
}

func ParseMavenLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, MavenLockExtractor{})
}
