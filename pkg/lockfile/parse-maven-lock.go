package lockfile

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	depsdevpb "deps.dev/api/v3"
	"deps.dev/util/maven"
	"deps.dev/util/semver"
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

	for _, lockPackage := range parsedLockfile.Dependencies {
		finalName := lockPackage.GroupID + ":" + lockPackage.ArtifactID

		pkgDetails := PackageDetails{
			Name:      finalName,
			Version:   lockPackage.ResolveVersion(*parsedLockfile),
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
		}
		if strings.TrimSpace(lockPackage.Scope) != "" {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, lockPackage.Scope)
		}
		details[finalName] = pkgDetails
	}

	// managed dependencies take precedent over standard dependencies
	for _, lockPackage := range parsedLockfile.ManagedDependencies {
		finalName := lockPackage.GroupID + ":" + lockPackage.ArtifactID
		pkgDetails := PackageDetails{
			Name:      finalName,
			Version:   lockPackage.ResolveVersion(*parsedLockfile),
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
		}
		if strings.TrimSpace(lockPackage.Scope) != "" {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, lockPackage.Scope)
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

type MavenLockExtractor2 struct {
	Client depsdevpb.InsightsClient
}

func (e MavenLockExtractor2) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pom.xml"
}

func (e MavenLockExtractor2) Extract(f DepFile) ([]PackageDetails, error) {
	ctx := context.Background()

	var project maven.Project
	if err := xml.NewDecoder(f).Decode(&project); err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	if err := project.Interpolate(); err != nil {
		return []PackageDetails{}, fmt.Errorf("could not interpolate Maven project %s: %w", project.ProjectKey.Name(), err)
	}

	details := map[string]PackageDetails{}

	for _, dep := range project.Dependencies {
		name := dep.Name()
		v, err := e.resolveVersion(ctx, dep)
		if err != nil {
			return []PackageDetails{}, err
		}
		pkgDetails := PackageDetails{
			Name:      name,
			Version:   v,
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
		}
		if dep.Scope != "" {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, string(dep.Scope))
		}
		details[name] = pkgDetails
	}

	// managed dependencies take precedent over standard dependencies
	for _, dep := range project.DependencyManagement.Dependencies {
		name := dep.Name()
		v, err := e.resolveVersion(ctx, dep)
		if err != nil {
			return []PackageDetails{}, err
		}
		pkgDetails := PackageDetails{
			Name:      name,
			Version:   v,
			Ecosystem: MavenEcosystem,
			CompareAs: MavenEcosystem,
		}
		if dep.Scope != "" {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, string(dep.Scope))
		}
		details[name] = pkgDetails
	}

	return maps.Values(details), nil
}

func (e MavenLockExtractor2) resolveVersion(ctx context.Context, dep maven.Dependency) (string, error) {
	constraint, err := semver.Maven.ParseConstraint(string(dep.Version))
	if err != nil {
		return "", fmt.Errorf("parsing Maven constraint %s: %w", dep.Version, err)
	}
	if constraint.IsSimple() {
		// Return the constraint if it is a simple version string.
		return constraint.String(), nil
	}

	// Otherwise return the greatest version matching the constraint.
	// TODO: invoke Maven resolver to decide the exact version.
	resp, err := e.Client.GetPackage(ctx, &depsdevpb.GetPackageRequest{
		PackageKey: &depsdevpb.PackageKey{
			System: depsdevpb.System_MAVEN,
			Name:   dep.Name(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("requesting versions of Maven package %s: %w", dep.Name(), err)
	}

	var result *semver.Version
	for _, ver := range resp.GetVersions() {
		v, _ := semver.Maven.Parse(ver.GetVersionKey().GetVersion())
		if constraint.MatchVersion(v) && result.Compare(v) < 0 {
			result = v
		}
	}

	return result.String(), nil
}

func ParseMavenLock2(depsdev depsdevpb.InsightsClient, pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, MavenLockExtractor2{Client: depsdev})
}
