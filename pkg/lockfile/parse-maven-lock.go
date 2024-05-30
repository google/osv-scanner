package lockfile

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"golang.org/x/exp/maps"
)

type MavenLockDependency struct {
	XMLName    xml.Name `xml:"dependency"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Scope      string   `xml:"scope"`
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
	XMLName             xml.Name              `xml:"project"`
	ModelVersion        string                `xml:"modelVersion"`
	GroupID             string                `xml:"groupId"`
	ArtifactID          string                `xml:"artifactId"`
	Properties          MavenLockProperties   `xml:"properties"`
	Dependencies        []MavenLockDependency `xml:"dependencies>dependency"`
	ManagedDependencies []MavenLockDependency `xml:"dependencyManagement>dependencies>dependency"`
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

	for _, lockPackage := range parsedLockfile.ManagedDependencies {
		finalName := lockPackage.GroupID + ":" + lockPackage.ArtifactID
		pkgDetails := PackageDetails{
			Name:      finalName,
			Version:   lockPackage.ResolveVersion(*parsedLockfile),
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, scope)
		}
		details[finalName] = pkgDetails
	}

	// standard dependencies take precedent over managed dependencies
	for _, lockPackage := range parsedLockfile.Dependencies {
		finalName := lockPackage.GroupID + ":" + lockPackage.ArtifactID

		pkgDetails := PackageDetails{
			Name:      finalName,
			Version:   lockPackage.ResolveVersion(*parsedLockfile),
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, scope)
		}
		details[finalName] = pkgDetails
	}

	return maps.Values(details), nil
}

var _ Extractor = MavenLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("pom.xml", MavenLockExtractor{})
}

func ParseMavenLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, MavenLockExtractor{})
}
